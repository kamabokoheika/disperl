package Disperl::Voice::Dave::MLSState;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Digest::SHA qw(sha256);

use Disperl::Voice::Dave::TLS qw(tls_u8 tls_u16 tls_u32 tls_u64 tls_opaqueV
                                 tls_varint Reader);
use Disperl::Voice::Dave::MLS qw(
    MLS_VERSION CIPHER_SUITE
    encode_leaf_node decode_leaf_node leaf_node_tbs
    encode_key_package decode_key_package key_package_tbs verify_key_package
    encode_group_context decode_group_context
    encode_sender decode_sender
    encode_proposal decode_proposal
    encode_commit decode_commit
    encode_framed_content decode_framed_content framed_content_tbs
    encode_public_message decode_public_message
    encode_welcome decode_welcome
    encode_group_info decode_group_info group_info_tbs
    encode_group_secrets decode_group_secrets
    encode_extension decode_extensions
    make_key_package_ref make_proposal_ref
    sign_with_label verify_with_label encrypt_context ref_hash
    user_id_identity identity_user_id
);
use Disperl::Voice::Dave::MLSTree qw(
    tree_node_count tree_capacity node_level parent_index direct_path copath
    tree_root_hash
);
use Disperl::Voice::Dave::KeySchedule qw(
    key_schedule_next key_schedule_from_joiner initial_key_schedule
    confirmation_tag media_key_base_secret sender_ratchet_key welcome_keys
);
use Disperl::Voice::Dave::Hpke qw(hpke_seal hpke_open);
use Disperl::Voice::Dave::AesGcm qw(aes128_gcm_encrypt_oneshot);
use Disperl::Voice::Dave::P256 qw(p256_uncompress p256_valid_public);

# MLS のグループ状態（DAVE 用サブセット）。
#
# ノードは index => { leaf => LeafNode } または { parent => ParentNode }。
# 葉は偶数 index、空のノードは存在しない（undef 扱い）。

my $ZERO32 = "\x00" x 32;

sub new {
    my ($class, %args) = @_;
    my $self = bless {
        user_id       => $args{user_id},
        signing_key   => $args{signing_key},        # 秘密鍵（hex 64）
        signature_pub => $args{signature_pub},      # 0x04||X||Y
        hpke_priv     => $args{hpke_priv},           # 秘密鍵（hex 64）
        hpke_pub      => $args{hpke_pub},            # 0x04||X||Y
        group_id      => $args{group_id} // '',
        epoch         => 0,
        leaf_count    => 1,
        nodes         => {},
        self_index    => 0,
        init_secret   => $ZERO32,
        epoch_secret  => '',
        exporter_secret => '',
        tree_hash     => '',
        confirmed_transcript_hash => '',
        interim_transcript_hash   => '',
        external_sender => undef,
        members       => {},
        key_packages  => {},        # user_id => 解釈済み KeyPackage
    }, $class;
    return $self;
}

sub epoch             { $_[0]->{epoch} }
sub self_index        { $_[0]->{self_index} }
sub leaf_count        { $_[0]->{leaf_count} }
sub group_id          { $_[0]->{group_id} }
sub tree_hash         { $_[0]->{tree_hash} }
sub exporter_secret   { $_[0]->{exporter_secret} }
sub confirmed_transcript_hash { $_[0]->{confirmed_transcript_hash} }
sub interim_transcript_hash   { $_[0]->{interim_transcript_hash} }
sub node { $_[0]->{nodes}{ $_[1] } }
sub external_sender { $_[0]->{external_sender} }

# ---------------------------------------------------------------- 外部送信者

# opaque SignaturePublicKey<V> || Credential
sub set_external_sender {
    my ($self, $bytes) = @_;
    my $r = Reader->new($bytes);
    my $sig_key = $r->reader_opaqueV;
    my $cred_type = $r->reader_u16;
    my $identity = $r->reader_opaqueV;

    $self->{external_sender} = {
        signature_key => $sig_key,
        credential    => { type => $cred_type, identity => $identity },
        raw           => $bytes,
    };
    return 1;
}

# ---------------------------------------------------------------- KeyPackage

sub _self_leaf_node {
    my ($self, %o) = @_;
    return {
        encryption_key   => $self->{hpke_pub},
        signature_key    => $self->{signature_pub},
        credential       => { identity => user_id_identity($self->{user_id}) },
        capabilities     => $o{capabilities} // {},
        leaf_node_source => 1,     # key_package
        lifetime         => { not_before => 0, not_after => (1 << 63) - 1 },
        extensions       => [],
    };
}

# LeafNode 自身の署名を付ける（encode_leaf_node は署名が無いと鍵を要求するため）
sub _sign_leaf {
    my ($self, $leaf) = @_;
    $leaf->{signature} = sign_with_label($self->{signing_key}, 'LeafNodeTBS',
                                         leaf_node_tbs($leaf));
    return $leaf;
}

# 自分の KeyPackage を作る（署名付き）。$user_id を渡すとその identity で作る。
sub create_key_package {
    my ($self, %args) = @_;

    my $leaf = $self->_self_leaf_node(capabilities => $args{capabilities});
    $leaf->{credential} = { identity => user_id_identity($args{user_id}) }
        if defined $args{user_id};
    $self->_sign_leaf($leaf);

    my $kp = {
        version      => MLS_VERSION,
        cipher_suite => CIPHER_SUITE,
        init_key     => $self->{hpke_pub},
        leaf_node    => $leaf,
        extensions   => [],
        signing_key  => $self->{signing_key},
    };
    my $bytes = encode_key_package($kp);
    $self->{last_key_package} = $bytes;
    return $bytes;
}

sub key_package_ref { return make_key_package_ref($_[1]) }

# ---------------------------------------------------------------- GroupContext

sub _group_context_bytes {
    my ($self) = @_;
    return encode_group_context({
        version      => MLS_VERSION,
        cipher_suite => CIPHER_SUITE,
        group_id     => $self->{group_id},
        epoch        => $self->{epoch},
        tree_hash    => $self->{tree_hash},
        confirmed_transcript_hash => $self->{confirmed_transcript_hash} // '',
        extensions   => [],
    });
}

sub _update_tree_hash {
    my ($self) = @_;
    my $node_count = tree_node_count($self->{leaf_count});
    $self->{tree_hash} = tree_root_hash(
        node_count => $node_count,
        resolver   => sub { $self->{nodes}{ $_[0] } },
    );
    return $self->{tree_hash};
}

sub _apply_key_schedule {
    my ($self, $ks) = @_;
    $self->{epoch_secret}    = $ks->{epoch_secret};
    $self->{exporter_secret} = $ks->{exporter_secret};
    $self->{init_secret}     = $ks->{init_secret};
    $self->{key_schedule}    = $ks;
    return 1;
}

# ---------------------------------------------------------------- グループ作成

# 自分だけのグループを作る（epoch 0）。
sub create_group {
    my ($self, %args) = @_;

    $self->{group_id}   = $args{group_id} // '';
    $self->{epoch}      = 0;
    $self->{leaf_count} = 1;
    $self->{self_index} = 0;
    $self->{nodes}      = { 0 => { leaf => $self->_sign_leaf($self->_self_leaf_node) } };
    $self->{members}    = { $self->{user_id} => 0 };
    $self->{confirmed_transcript_hash} = '';
    $self->{interim_transcript_hash}   = '';

    $self->_update_tree_hash;

    my $ctx = $self->_group_context_bytes;
    my $ks = key_schedule_next(
        init_secret   => $ZERO32,
        commit_secret => $ZERO32,
        psk_secret    => $ZERO32,
        context       => $ctx,
        confirmed_transcript_hash => '',
    );
    $self->{interim_transcript_hash} = sha256('' . $ks->{confirmation_tag});
    $self->_apply_key_schedule($ks);
    return 1;
}

# ---------------------------------------------------------------- ratchet tree

# Node = uint8 node_type(1=leaf,2=parent) + 本体。optional<Node> は uint8 present 前置。
# group_info の ratchet_tree 拡張の中身（optional<Node> のベクタ）をデコードする。
sub decode_ratchet_tree {
    my ($self, $tree_bytes) = @_;

    my $r = Reader->new($tree_bytes);
    my @nodes;
    while ($r->reader_remaining > 0) {
        my $present = $r->reader_u8;
        die "bad optional flag $present\n" unless $present == 0 || $present == 1;
        if ($present) {
            my $type = $r->reader_u8;
            if ($type == 1) {
                push @nodes, { leaf => decode_leaf_node($r) };
            } elsif ($type == 2) {
                push @nodes, { parent => _decode_parent_node($r) };
            } else {
                die "bad NodeType $type\n";
            }
        } else {
            push @nodes, undef;
        }
    }
    return \@nodes;
}

sub _decode_parent_node {
    my ($r) = @_;
    my $enc = $r->reader_opaqueV;
    my $ph  = $r->reader_opaqueV;
    my $un  = $r->reader_opaqueV;
    return {
        encryption_key  => $enc,
        parent_hash     => $ph,
        unmerged_leaves => [ unpack 'N*', $un ],
    };
}

sub _encode_parent_node {
    my ($n) = @_;
    my $un = $n->{unmerged_leaves};
    $un = pack('N*', @$un) if ref $un eq 'ARRAY';
    return tls_u8(2)
         . tls_opaqueV($n->{encryption_key})
         . tls_opaqueV($n->{parent_hash} // '')
         . tls_opaqueV($un // '');
}

# 全ノード（末端の blank は省略）をシリアライズする
sub encode_ratchet_tree {
    my ($self) = @_;

    my $node_count = tree_node_count($self->{leaf_count});

    # 最後の非 blank ノードまで
    my $last = $node_count - 1;
    $last-- while $last > 0 && !$self->{nodes}{$last};

    my $out = '';
    for my $i (0 .. $last) {
        my $node = $self->{nodes}{$i};
        if (!$node) {
            $out .= tls_u8(0);
        } elsif ($i % 2 == 0) {
            $out .= tls_u8(1) . tls_u8(1) . encode_leaf_node($node->{leaf});
        } else {
            $out .= _encode_parent_node($node->{parent});
        }
    }
    return $out;
}

sub _load_tree {
    my ($self, $nodes) = @_;

    # 葉数を決める: 最後の非 blank 葉
    my $last_leaf_index = -1;
    for my $i (0 .. $#$nodes) {
        next unless $nodes->[$i] && $i % 2 == 0;
        $last_leaf_index = $i / 2;
    }
    die "ratchet tree has no leaves\n" if $last_leaf_index < 0;

    my $capacity = tree_capacity($last_leaf_index + 1);
    $self->{leaf_count} = $capacity;

    $self->{nodes} = {};
    $self->{members} = {};
    for my $i (0 .. $#$nodes) {
        my $n = $nodes->[$i];
        next unless $n;
        if ($i % 2 == 0) {
            $self->{nodes}{$i} = $n;
            my $uid = identity_user_id($n->{leaf}{credential}{identity});
            $self->{members}{$uid} = $i / 2 if defined $uid;
        } else {
            $self->{nodes}{$i} = $n;
        }
    }

    my $uid = $self->{user_id};
    die "self is not in the ratchet tree\n"
        unless exists $self->{members}{$uid};
    $self->{self_index} = $self->{members}{$uid};
    return 1;
}

# ---------------------------------------------------------------- Welcome 処理

# Welcome を処理してグループに参加する。
#   $welcome_bytes  MLSMessage の body（Welcome）
sub process_welcome {
    my ($self, $welcome_bytes) = @_;

    my $w = decode_welcome($welcome_bytes);
    die "cipher suite mismatch\n" unless $w->{cipher_suite} == CIPHER_SUITE;

    # 自分の KeyPackage に対応するエントリを探す
    my $my_ref = $self->{last_key_package}
        ? make_key_package_ref($self->{last_key_package})
        : undef;
    die "no key package generated\n" unless defined $my_ref;

    my ($entry) = grep { $_->{key_package_ref} eq $my_ref } @{ $w->{secrets} };
    die "welcome does not address this client\n" unless $entry;

    # GroupSecrets を HPKE で開く（EncryptWithLabel(init_key, "Welcome", "", ...)）
    my $info = encrypt_context('Welcome', '');
    my $gs_bytes = hpke_open(
        $entry->{kem_output},
        $self->{hpke_priv},
        p256_uncompress($self->{hpke_pub}),
        $entry->{ciphertext},
        $info,
        '',
    );
    my $gs = decode_group_secrets($gs_bytes);

    my $joiner_secret = $gs->{joiner_secret};
    die "bad joiner secret length\n" unless length $joiner_secret == 32;

    # welcome_secret から key/nonce を出して GroupInfo を復号する
    my $wk = welcome_keys($joiner_secret);
    die "encrypted_group_info too short\n" if length($w->{encrypted_group_info}) < 16;
    my $ct  = substr($w->{encrypted_group_info}, 0, length($w->{encrypted_group_info}) - 16);
    my $tag = substr($w->{encrypted_group_info}, -16);
    my $gi_bytes = aes128_gcm_decrypt_oneshot($wk->{key}, $wk->{nonce}, $ct, '', $tag);

    my $gi = decode_group_info($gi_bytes);

    # ratchet_tree 拡張（0x0002）を取り出す
    my ($tree_ext) = grep { $_->{type} == 0x0002 } @{ $gi->{extensions} };
    die "GroupInfo has no ratchet_tree extension\n" unless $tree_ext;

    my $nodes = $self->decode_ratchet_tree($tree_ext->{data});
    $self->_load_tree($nodes);

    # GroupInfo の署名検証（signer の葉の signature_key）
    my $signer_leaf = ($self->{nodes}{ $gi->{signer_index} * 2 } // {})->{leaf};
    die "GroupInfo signer leaf is blank\n" unless $signer_leaf;
    my $signer_pub = p256_uncompress($signer_leaf->{signature_key});
    my $gi_tbs = $gi->{group_context_bytes}
               . encode_extensions($gi->{extensions})
               . tls_opaqueV($gi->{confirmation_tag})
               . tls_u32($gi->{signer_index});
    die "GroupInfo signature invalid\n"
        unless verify_with_label($signer_pub, 'GroupInfoTBS', $gi_tbs, $gi->{signature});

    # GroupContext を採用
    my $gc = $gi->{group_context};
    die "cipher suite mismatch in GroupContext\n"
        unless $gc->{cipher_suite} == CIPHER_SUITE;

    $self->{group_id}   = $gc->{group_id};
    $self->{epoch}      = $gc->{epoch};
    $self->{tree_hash}  = $gc->{tree_hash};
    $self->{confirmed_transcript_hash} = $gc->{confirmed_transcript_hash};

    # ツリーの整合性（tree_hash の一致）を確認
    my $computed = $self->_update_tree_hash;
    die "tree hash mismatch\n" unless $computed eq $gc->{tree_hash};

    # psk_secret（DAVE では PSK を使わない）
    my $psk_secret = $ZERO32;

    my $ctx = $self->_group_context_bytes;
    my $ks = key_schedule_from_joiner(
        joiner_secret => $joiner_secret,
        psk_secret    => $psk_secret,
        context       => $ctx,
        confirmed_transcript_hash => $gc->{confirmed_transcript_hash},
    );

    $self->{interim_transcript_hash} =
        sha256($gc->{confirmed_transcript_hash} . $gi->{confirmation_tag});

    $self->_apply_key_schedule($ks);
    return 1;
}

# ---------------------------------------------------------------- Commit 処理

# 外部送信者などからの Commit（PublicMessage）を適用して epoch を進める。
#   $pm_bytes  PublicMessage のバイト列（MLSMessage のヘッダは含めない）
#   $proposals 提案のキャッシュ [{proposal=>...}] （参照の解決用）
sub process_commit {
    my ($self, $pm_bytes, $proposals) = @_;

    $proposals ||= [];
    my $pm = decode_public_message($pm_bytes);
    my $content = $pm->{content};
    die "not a commit\n" unless $content->{content_type} eq 'commit';

    my $commit = $content->{commit};

    # 提案を解決
    my @applied;
    for my $p (@{ $commit->{proposals} }) {
        if ($p->{kind} == 1) {
            push @applied, $p->{proposal};
        } else {
            my ($hit) = grep {
                my $ref = $_->{ref} // make_proposal_ref($_->{authenticated_content} // '');
                defined $ref && $ref eq $p->{ref};
            } @$proposals;
            die "unknown proposal reference\n" unless $hit;
            push @applied, $hit->{proposal};
        }
    }

    # FramedContentTBS を作って署名検証（送信者 = 外部送信者 or member）
    my $ctx = $self->_group_context_bytes;
    my $tbs = framed_content_tbs($content, $ctx);
    my $sender = $content->{sender};
    my $pub;
    if (($sender->{code} // 1) == 1) {
        my $leaf = ($self->{nodes}{ $sender->{leaf_index} * 2 } // {})->{leaf};
        die "commit sender leaf is blank\n" unless $leaf;
        $pub = p256_uncompress($leaf->{signature_key});
    } else {
        die "no external sender configured\n" unless $self->{external_sender};
        $pub = p256_uncompress($self->{external_sender}{signature_key});
    }
    die "commit signature invalid\n"
        unless verify_with_label($pub, 'FramedContentTBS', $tbs, $pm->{signature});

    # ツリーを更新（追加分の葉を反映）
    $self->_apply_proposals(\@applied);

    # path があれば commit_secret を導出する。DAVE の外部 commit は path を持つ。
    my $commit_secret = $ZERO32;

    my $new_confirmed = sha256($self->{interim_transcript_hash} . $tbs);

    $self->{epoch}++;
    my $new_ctx = encode_group_context({
        version      => MLS_VERSION,
        cipher_suite => CIPHER_SUITE,
        group_id     => $self->{group_id},
        epoch        => $self->{epoch},
        tree_hash    => $self->{tree_hash},
        confirmed_transcript_hash => $new_confirmed,
        extensions   => [],
    });

    my $ks = key_schedule_next(
        init_secret   => $self->{init_secret},
        commit_secret => $commit_secret,
        psk_secret    => $ZERO32,
        context       => $new_ctx,
        confirmed_transcript_hash => $new_confirmed,
    );

    # confirmation_tag の検証
    die "confirmation tag mismatch\n"
        unless $ks->{confirmation_tag} eq ($pm->{confirmation_tag} // '');

    $self->{confirmed_transcript_hash} = $new_confirmed;
    $self->{interim_transcript_hash} =
        sha256($new_confirmed . $ks->{confirmation_tag});
    $self->_apply_key_schedule($ks);

    return 1;
}

# Add / Remove をツリーに反映する
sub _apply_proposals {
    my ($self, $applied) = @_;

    my @removed;
    my @added;
    for my $p (@$applied) {
        if ($p->{type} eq 'add') {
            push @added, $p->{key_package};
        } elsif ($p->{type} eq 'remove') {
            push @removed, $p->{removed};
        }
    }

    # remove: 葉を blank に
    for my $idx (@removed) {
        my $uid = $self->{user_id};
        delete $self->{members}{$_} for grep { $self->{members}{$_} == $idx } keys %{ $self->{members} };
        delete $self->{nodes}{ $idx * 2 };
    }

    # add: 空いている最小の葉に置く
    for my $kp (@added) {
        my $idx = $self->_first_free_leaf;
        if ($idx > $self->{leaf_count} - 1) {
            $self->_grow_tree(tree_capacity($idx + 1));
            $idx = $self->_first_free_leaf;
        }
        $self->{nodes}{ $idx * 2 } = { leaf => $kp->{leaf_node} };
        my $uid = identity_user_id($kp->{leaf_node}{credential}{identity});
        $self->{members}{$uid} = $idx if defined $uid;
    }

    $self->_update_tree_hash;
    return 1;
}

sub _first_free_leaf {
    my ($self) = @_;
    for my $i (0 .. $self->{leaf_count} - 1) {
        return $i unless $self->{nodes}{ $i * 2 };
    }
    return $self->{leaf_count};
}

# 完全二分木を拡張する（既存の葉の位置は保つ）
sub _grow_tree {
    my ($self, $capacity) = @_;
    return 1 if $capacity <= $self->{leaf_count};

    my %old = %{ $self->{nodes} };
    $self->{nodes} = {};
    for my $i (keys %old) {
        next unless $i % 2 == 0;    # 葉だけ移す（親は作り直す）
        $self->{nodes}{$i} = $old{$i};
    }
    $self->{leaf_count} = $capacity;
    return 1;
}

# ---------------------------------------------------------------- exporter

sub export_media_base_secret {
    my ($self, $user_id) = @_;
    $user_id = $self->{user_id} unless defined $user_id;
    die "no exporter_secret\n" unless length $self->{exporter_secret};
    return media_key_base_secret($self->{exporter_secret}, $user_id);
}

sub export_secret {
    my ($self, $label, $context, $len) = @_;
    require Disperl::Voice::Dave::Hkdf;
    return Disperl::Voice::Dave::Hkdf::mls_exporter(
        $self->{exporter_secret}, $label, $context, $len);
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::MLSState - MLS のグループ状態（DAVE 用サブセット）

=head1 DESCRIPTION

DAVE クライアントが必要とする受信側の処理:
Welcome で参加、Commit で epoch を進める、exporter からメディア鍵を出す。

Commit の生成は行わない（DAVE では音声ゲートウェイが外部送信者として
Commit を配る）。=cut
