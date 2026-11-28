package Disperl::Voice::Dave;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Disperl::Voice::Dave::TLS qw(tls_u8 tls_u16 tls_u32 tls_opaqueV tls_varint Reader);
use Disperl::Voice::Dave::Util qw(uleb128_encode uleb128_decode random_bytes);
use Disperl::Voice::Dave::MLS qw(MLS_VERSION CIPHER_SUITE encode_mls_message
                                 decode_mls_message make_key_package_ref
                                 make_proposal_ref user_id_identity);
use Disperl::Voice::Dave::MLSState;
use Disperl::Voice::Dave::KeySchedule qw(media_key_base_secret sender_ratchet_key);
use Disperl::Voice::Dave::AesGcm qw(aes128_gcm_encrypt_oneshot aes128_gcm_decrypt_oneshot);
use Disperl::Voice::Dave::P256 qw(p256_pubkey p256_serialize);
use Disperl::Voice::Dave::Hkdf qw(mls_exporter);

# DAVE（Discord の E2EE）クライアント。
# 仕様: https://github.com/discord/dave-protocol
#
# バイナリメッセージ = uint16 sequence_number || uint8 opcode || payload
#  受信 21 prepare_transition / 22 execute_transition / 24 prepare_epoch
#       25 external_sender / 26 key_package / 27 proposals
#       28 commit_welcome / 29 announce_commit / 30 welcome / 31 invalid_commit_welcome
#  送信 23 ready_for_transition / 26 key_package / 27 proposals
#       28 commit_welcome / 31 invalid_commit_welcome
#
# メディアフレーム（Opus は全体を暗号化）:
#   ciphertext || tag(8) || ULEB128(nonce) || <unencrypted ranges> || size(1) || 0xFA 0xFA

use constant OP_PREPARE_TRANSITION   => 21;
use constant OP_EXECUTE_TRANSITION   => 22;
use constant OP_READY_FOR_TRANSITION => 23;
use constant OP_PREPARE_EPOCH        => 24;
use constant OP_EXTERNAL_SENDER      => 25;
use constant OP_KEY_PACKAGE          => 26;
use constant OP_PROPOSALS            => 27;
use constant OP_COMMIT_WELCOME       => 28;
use constant OP_ANNOUNCE_COMMIT      => 29;
use constant OP_WELCOME              => 30;
use constant OP_INVALID_COMMIT       => 31;

use constant TAG_BYTES    => 8;        # 切り詰めた AES-GCM タグ
use constant MARKER       => "\xfa\xfa";
use constant MAX_PROTOCOL => 1;

# 無音フレームは平文のまま通過させる（libdave と同じ）
our $OPUS_SILENCE = "\xf8\xff\xfe";

sub new {
    my ($class, %args) = @_;

    my $user_id = $args{user_id} or die "user_id required\n";
    my $self = bless {
        user_id          => $user_id,
        protocol_version => $args{protocol_version} // 1,
        signing_key      => $args{signing_key},
        signature_pub    => $args{signature_pub},
        hpke_priv        => $args{hpke_priv},
        hpke_pub         => $args{hpke_pub},
        seq              => 0,
        transition_id    => 0,
        epoch            => 0,
        state            => 'idle',      # idle | pending | ready
        external_sender  => undef,
        proposals        => [],
        ratchets         => {},          # user_id => { base => ..., keys => { gen => key } }
        nonce            => 0,
        outbound         => [],          # 送信待ちのバイナリメッセージ
        session          => undef,
        log              => $args{log} // sub { },
    }, $class;

    $self->setup_keys unless defined $self->{signing_key} && length $self->{signing_key};
    return $self;
}

sub user_id          { $_[0]->{user_id} }
sub protocol_version { $_[0]->{protocol_version} }
sub transition_id    { $_[0]->{transition_id} }
sub state            { $_[0]->{state} }
sub mls              { $_[0]->{session} }
sub next_seq         { return $_[0]->{seq}++ & 0xffff }

sub log {
    my ($self, $msg) = @_;
    $self->{log}->($msg);
    return 1;
}

# ---------------------------------------------------------------- 鍵素材

# 長期鍵（署名鍵 / HPKE 鍵）を用意する。既に持っていれば使う。
# ランダム鍵を作るので、メンバー変わりの同一アイデンティティが必要なら
# seed_file で保存・再利用すること。
sub setup_keys {
    my ($self, %args) = @_;
    return 1 if defined $self->{signing_key} && length $self->{signing_key}
             && defined $self->{hpke_priv} && length $self->{hpke_priv};

    my $seed = $args{seed_file};
    if ($seed && -e $seed) {
        $self->_load_keys($seed);
        return 1;
    }

    my $sig_priv = _random_scalar();
    my $sig_pub  = p256_serialize(p256_pubkey($sig_priv));
    my $hpke_priv = _random_scalar();
    my $hpke_pub  = p256_serialize(p256_pubkey($hpke_priv));

    $self->{signing_key}   = $sig_priv;
    $self->{signature_pub} = $sig_pub;
    $self->{hpke_priv}     = $hpke_priv;
    $self->{hpke_pub}      = $hpke_pub;

    $self->_save_keys($seed) if $seed;
    return 1;
}

sub _save_keys {
    my ($self, $path) = @_;
    open my $fh, '>', $path or die "cannot write $path: $!\n";
    print {$fh} join("\n", $self->{signing_key}, $self->{hpke_priv}), "\n";
    close $fh;
    chmod 0600, $path;
    return 1;
}

sub _load_keys {
    my ($self, $path) = @_;
    open my $fh, '<', $path or die "cannot read $path: $!\n";
    my @l = <$fh>;
    close $fh;
    chomp @l;
    die "bad key file $path\n" unless @l >= 2;
    $self->{signing_key} = $l[0];
    $self->{hpke_priv}   = $l[1];
    $self->{signature_pub} = p256_serialize(p256_pubkey($l[0]));
    $self->{hpke_pub}      = p256_serialize(p256_pubkey($l[1]));
    return 1;
}

sub _random_scalar {
    my $b = random_bytes(32);
    require Disperl::Voice::Dave::Scalar;
    my $hex = Disperl::Voice::Dave::Scalar::sc_to_hex(
        Disperl::Voice::Dave::Scalar::sc_reduce(
            Disperl::Voice::Dave::Scalar::sc_from_hex(unpack 'H*', $b)));
    return $hex;
}

# ---------------------------------------------------------------- セッション状態

sub _new_session {
    my ($self) = @_;
    $self->{session} = Disperl::Voice::Dave::MLSState->new(
        user_id       => $self->{user_id},
        signing_key   => $self->{signing_key},
        signature_pub => $self->{signature_pub},
        hpke_priv     => $self->{hpke_priv},
        hpke_pub      => $self->{hpke_pub},
    );
    # 先に届いた external_sender を新しいセッションに渡す
    $self->{session}->set_external_sender($self->{external_sender})
        if defined $self->{external_sender};
    return $self->{session};
}

# 送信待ちのバイナリメッセージを取り出す
sub drain_outbound {
    my ($self) = @_;
    my @out = @{ $self->{outbound} };
    $self->{outbound} = [];
    return @out;
}

sub _enqueue {
    my ($self, $opcode, $payload) = @_;
    push @{ $self->{outbound} }, $self->_frame($opcode, $payload);
    return 1;
}

sub _frame {
    my ($self, $opcode, $payload) = @_;
    return tls_u16($self->next_seq) . tls_u8($opcode) . ($payload // '');
}

# ---------------------------------------------------------------- 受信処理

# バイナリメッセージを 1 つ処理する。JSON メッセージは呼び出し側で扱う。
sub handle_binary {
    my ($self, $bytes) = @_;

    die "binary message too short\n" if length($bytes) < 3;
    my ($seq, $op) = unpack 'nC', $bytes;
    my $payload = substr($bytes, 3);

    warn sprintf("[dave] bin op=%d len=%d\n", $op, length $payload);

    # opcode 26 は投機的に seq 無しの可能性を許す
    if ($op < 20 || $op > 31) {
        my $alt = ord substr($bytes, 0, 1);
        if ($alt >= 20 && $alt <= 31) {
            $op = $alt;
            $payload = substr($bytes, 1);
        } else {
            die "unknown DAVE opcode $op\n";
        }
    }

    if ($op == OP_EXTERNAL_SENDER)     { return $self->_on_external_sender($payload) }
    if ($op == OP_KEY_PACKAGE)         { return $self->_on_key_package($payload) }
    if ($op == OP_PROPOSALS)           { return $self->_on_proposals($payload) }
    if ($op == OP_ANNOUNCE_COMMIT)     { return $self->_on_announce_commit($payload) }
    if ($op == OP_WELCOME)             { return $self->_on_welcome($payload) }
    if ($op == OP_INVALID_COMMIT)      { return 1 }

    $self->log("unhandled DAVE opcode $op");
    return 1;
}

# JSON の DAVE メッセージ（21/22/24）を処理する
sub handle_json {
    my ($self, $data) = @_;
    return 1 unless ref $data eq 'HASH';

    my $op = $data->{op} // -1;

    if ($op == OP_PREPARE_TRANSITION) {
        my $tid = $data->{d}{transition_id} // 0;
        $self->{transition_id} = $tid;
        $self->{protocol_version} = $data->{d}{protocol_version}
            if defined $data->{d}{protocol_version};
        # 全ユーザーのキーラチェットをセットアップ（libdave 準拠）
        $self->_setup_key_ratchets;
        # 0 は初期化なので即座に実行してよい
        $self->_ready_for_transition($tid) if $tid == 0;
        return 1;
    }

    if ($op == OP_EXECUTE_TRANSITION) {
        my $tid = $data->{d}{transition_id} // 0;
        $self->{transition_id} = $tid;
        $self->{state} = 'ready';
        $self->_reset_ratchets;
        $self->_setup_key_ratchets;
        return 1;
    }

    if ($op == OP_PREPARE_EPOCH) {
        my $epoch = $data->{d}{epoch} // 0;
        $self->{epoch} = $epoch;
        $self->{protocol_version} = $data->{d}{protocol_version}
            if defined $data->{d}{protocol_version};
        # epoch 1 = 新しい MLS グループを作る
        if ($epoch == 1) {
            $self->_new_session;
            $self->{state} = 'pending';
            $self->send_key_package;
        }
        return 1;
    }

    return 1;
}

# 全ユーザーのキーラチェットを初期化（libdave 準拠）
sub _setup_key_ratchets {
    my ($self) = @_;
    my $sess = $self->{session} or return 1;
    for my $uid (keys %{ $sess->{members} // {} }) {
        my $base = $self->_base_secret_for($uid) or next;
        $self->_ratchet_key($uid, $base, 0);
    }
    # 自分自身も（メンバーに含まれていない場合）
    my $base = $self->_self_base_secret or return 1;
    $self->_ratchet_key($self->{user_id}, $base, 0);
    return 1;
}

sub _ready_for_transition {
    my ($self, $tid) = @_;
    my $payload = '{"op":23,"d":{"transition_id":' . int($tid) . '}}';
    push @{ $self->{outbound_json} }, $payload;
    return 1;
}

sub drain_outbound_json {
    my ($self) = @_;
    my @out = @{ $self->{outbound_json} || [] };
    $self->{outbound_json} = [];
    return @out;
}

# ---------------------------------------------------------------- MLS メッセージ

sub _on_external_sender {
    my ($self, $payload) = @_;

    # ExternalSender = SignaturePublicKey<V> || Credential
    $self->{external_sender} = $payload;
    if ($self->{session}) {
        $self->{session}->set_external_sender($payload);
    }
    $self->log('DAVE external sender stored');
    return 1;
}

sub _on_key_package {
    my ($self, $payload) = @_;
    # 音声ゲートウェイから鍵パッケージが配られることはないが、
    # 形式だけ受け取れるようにしておく。
    $self->{peer_key_package} = $payload;
    return 1;
}

sub _on_proposals {
    my ($self, $payload) = @_;

    my $r = Reader->new($payload);
    my $operation = $r->reader_u8;

    if ($operation == 0) {    # append
        my $msgs = $r->reader_opaqueV;
        my $mr = Reader->new($msgs);
        while ($mr->reader_remaining > 0) {
            my $body = $mr->reader_opaqueV;
            push @{ $self->{proposals} }, $body;
        }
    } elsif ($operation == 1) {    # revoke
        my $refs = $r->reader_opaqueV;
        my $rr = Reader->new($refs);
        while ($rr->reader_remaining > 0) {
            my $ref = $rr->reader_opaqueV;
            $self->{proposals} = [
                grep { ($_->{ref} // '') ne $ref } @{ $self->{proposals} }
            ];
        }
    }
    return 1;
}

sub proposals { $_[0]->{proposals} }

sub _on_announce_commit {
    my ($self, $payload) = @_;

    my $r = Reader->new($payload);
    my $tid = $r->reader_u16;
    my $msg = $r->reader_rest;

    $self->{transition_id} = $tid;
    my $mls = decode_mls_message($msg);
    my $ok = eval { $self->{session}->process_commit($mls->{body}, $self->{proposals}); 1 };
    unless ($ok) {
        my $err = $@ || 'commit failed';
        $err =~ s/\s+\z//;
        $self->log("DAVE commit failed: $err");
        push @{ $self->{outbound_json} },
            '{"op":31,"d":{"transition_id":' . int($tid) . '}}';
        return 0;
    }

    $self->{proposals} = [];
    $self->_ready_for_transition($tid);
    return 1;
}

sub _on_welcome {
    my ($self, $payload) = @_;

    my $r = Reader->new($payload);
    my $tid = $r->reader_u16;
    my $msg = $r->reader_rest;

    $self->{transition_id} = $tid;
    my $mls = decode_mls_message($msg);
    my $ok = eval { $self->{session}->process_welcome($mls->{body}); 1 };
    unless ($ok) {
        my $err = $@ || 'welcome failed';
        $err =~ s/\s+\z//;
        $self->log("DAVE welcome failed: $err");
        push @{ $self->{outbound_json} },
            '{"op":31,"d":{"transition_id":' . int($tid) . '}}';
        return 0;
    }

    $self->_reset_ratchets;
    $self->{state} = 'ready';
    $self->_ready_for_transition($tid);
    return 1;
}

# ---------------------------------------------------------------- 鍵パッケージ送信

sub send_key_package {
    my ($self) = @_;
    my $sess = $self->{session} or return 0;

    my $kp = $sess->create_key_package;    # 生バイト列
    $self->_enqueue(OP_KEY_PACKAGE, $kp);  # encode_mls_message は不要（op 26 は生の KeyPackage）
    return 1;
}

# ---------------------------------------------------------------- メディア暗号

# 送信フレームを DAVE で包む。無音フレームは平文で通す。
# 戻り値は ciphertext || tag(8) || ULEB128(nonce) || ULEB128 ranges || size || 0xFAFA


# 送信: 自分の世代鍵で Opus フレームを暗号化する
sub encrypt_frame {
    my ($self, $opus) = @_;

    return $opus if $opus eq $OPUS_SILENCE;    # 無音は平文で通す

    my $base = $self->_self_base_secret or return $opus;

    my $nonce = $self->{nonce} & 0xffffffff;
    $self->{nonce} = ($nonce + 1) & 0xffffffff;

    my $generation = $nonce >> 24;
    my $key = $self->_ratchet_key($self->{user_id}, $base, $generation);
    return $opus unless defined $key;

    my $full_nonce = ("\x00" x 8) . pack('V', $nonce);
    my ($ct, $tag) = aes128_gcm_encrypt_oneshot($key, $full_nonce, $opus, '', TAG_BYTES);

    my $uleb = uleb128_encode($nonce);
    my $supp_size = TAG_BYTES + length($uleb) + 1 + 2;
    return $ct . $tag . $uleb
         . tls_u8($supp_size) . MARKER;
}

# 受信: 送信者の世代鍵で復号する
sub decrypt_frame {
    my ($self, $frame, $sender_user_id) = @_;

    return $frame if $frame eq $OPUS_SILENCE;
    return $frame if length($frame) < TAG_BYTES + 3;
    return $frame unless substr($frame, -2) eq MARKER;

    my $supp_size = ord substr($frame, -3, 1);
    return $frame if $supp_size < TAG_BYTES + 3 || $supp_size > length($frame);

    my $supp_start = length($frame) - $supp_size;
    my $tag = substr($frame, $supp_start, TAG_BYTES);

    my $pos = $supp_start + TAG_BYTES;
    my ($nonce, $nlen) = eval { uleb128_decode($frame, $pos) };
    return $frame unless defined $nonce;
    my $npos = $pos + $nlen;

    # 暗号化されていない範囲（Opus では通常 0 個）
    my @ranges;
    $pos = $npos;
    while ($pos < length($frame) - 3) {
        my ($off, $olen) = eval { uleb128_decode($frame, $pos) };
        return $frame unless defined $off;
        my $p1 = $pos + $olen;
        my ($len, $llen) = eval { uleb128_decode($frame, $p1) };
        return $frame unless defined $len;
        push @ranges, [$off, $len];
        $pos = $p1 + $llen;
    }

    # AAD と暗号文を組み立てる
    my ($aad, $ct) = ('', '');
    my $idx = 0;
    for my $rg (@ranges) {
        my ($off, $len) = @$rg;
        $ct  .= substr($frame, $idx, $off - $idx) if $off > $idx;
        $aad .= substr($frame, $off, $len);
        $idx = $off + $len;
    }
    $ct .= substr($frame, $idx, $supp_start - $idx) if $supp_start > $idx;

    my $base = $self->_base_secret_for($sender_user_id);
    return $frame unless defined $base;

    my $generation = $nonce >> 24;
    # 複数のジェネレーションキーを試す（libdave 準拠）
    my $pt;
    for my $g ($generation, ($generation + 1) % 256, ($generation + 255) % 256) {
        my $key = $self->_ratchet_key($sender_user_id, $base, $g);
        next unless defined $key;
        my $full_nonce = ("\x00" x 8) . pack('V', $nonce);
        $pt = eval { aes128_gcm_decrypt_oneshot($key, $full_nonce, $ct, $aad, $tag) };
        last if defined $pt;
    }
    return $frame unless defined $pt;    # 復号できなければそのまま返す

    # 平文を範囲に戻す
    my $out = '';
    my $src = 0;
    $idx = 0;
    for my $rg (@ranges) {
        my ($off, $len) = @$rg;
        my $n = $off - $idx;
        $out .= substr($pt, $src, $n) if $n > 0;
        $src += $n;
        $out .= substr($frame, $off, $len);
        $idx = $off + $len;
    }
    my $rest = $supp_start - $idx;
    $out .= substr($pt, $src, $rest) if $rest > 0;
    return $out;
}

# ---------------------------------------------------------------- ラチェット

sub _self_base_secret {
    my ($self) = @_;
    return $self->_base_secret_for($self->{user_id});
}

sub _base_secret_for {
    my ($self, $user_id) = @_;
    my $sess = $self->{session} or return undef;
    my $exporter = $sess->exporter_secret;
    return undef unless length $exporter;
    return media_key_base_secret($exporter, $user_id);
}

sub _ratchet_key {
    my ($self, $user_id, $base, $generation) = @_;

    my $id = "$user_id:" . unpack('H*', $base);
    my $cache = $self->{ratchets}{$id} ||= { keys => {} };
    return $cache->{keys}{$generation} if exists $cache->{keys}{$generation};

    my $key = eval { sender_ratchet_key($base, $generation) };
    return undef unless defined $key;
    $cache->{keys}{$generation} = $key;
    return $key;
}

sub _reset_ratchets {
    my ($self) = @_;
    $self->{ratchets} = {};
    $self->{nonce}    = 0;
    return 1;
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave - Discord の E2EE（DAVE）

=head1 SYNOPSIS

    my $dave = Disperl::Voice::Dave->new(user_id => 123456789012345678);
    $dave->setup_keys;                  # 鍵を生成（保存は呼び出し側の責務）

    # voice gateway からの DAVE メッセージ
    $dave->handle_json($msg)   if $msg->{op} == 24;
    $dave->handle_binary($bin) if $binary;

    # 送信キューに積まれた MLS メッセージを WS に流す
    for my $json ($dave->drain_outbound_json) { $ws->send_text($json) }
    for my $bin  ($dave->drain_outbound)      { $ws->send_frame(0x2, $bin) }

    # メディアフレーム
    my $frame = $dave->encrypt_frame($opus);
    my $opus  = $dave->decrypt_frame($frame, $sender_user_id);

=cut
