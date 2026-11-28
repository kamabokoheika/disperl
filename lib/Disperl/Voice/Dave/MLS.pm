package Disperl::Voice::Dave::MLS;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';
use Digest::SHA qw(sha256);

use Disperl::Voice::Dave::TLS qw(
    tls_u8 tls_u16 tls_u32 tls_u64 tls_opaqueV tls_varint Reader
);
use Disperl::Voice::Dave::P256 qw(
    p256_sign p256_verify p256_pubkey p256_serialize p256_uncompress p256_valid_public
);

our @EXPORT = ();
our @EXPORT_OK = qw(
    sign_with_label verify_with_label sign_content encrypt_context ref_hash
    encode_credential decode_credential
    encode_capabilities decode_capabilities
    encode_leaf_node decode_leaf_node leaf_node_tbs
    encode_key_package decode_key_package key_package_tbs verify_key_package
    encode_group_context decode_group_context
    encode_sender decode_sender
    encode_proposal decode_proposal
    encode_commit decode_commit
    encode_framed_content decode_framed_content framed_content_tbs
    encode_framed_content_auth_data decode_framed_content_auth_data
    encode_public_message decode_public_message
    encode_mls_message decode_mls_message
    encode_encrypted_group_secrets decode_encrypted_group_secrets
    encode_welcome decode_welcome
    encode_group_info decode_group_info group_info_tbs
    encode_update_path decode_update_path
    encode_parent_node decode_parent_node
    encode_group_secrets decode_group_secrets
    encode_extension decode_extensions encode_extensions
    make_key_package_ref make_proposal_ref
    user_id_identity identity_user_id
    MLS_VERSION CIPHER_SUITE
);

# MLS 1.0 のサブセット（ciphersuite 2: P-256 + AES-128-GCM + SHA-256）。
# DAVE が必要とする範囲だけ実装する:
#   - basic credential（identity = ユーザー ID の big-endian 8 バイト）
#   - external sender（voice gateway）
#   - Add / Remove proposal
#   - PublicMessage（ハンドシェイクは平文）
#
# 長さフィールドは RFC 9420 §1.2 の可変長整数（<V>）を使う。固定長の
# uint8/uint16/uint32 ヘッダではないので注意。

use constant MLS_VERSION  => 1;    # mls10
use constant CIPHER_SUITE => 2;    # DHKEM_P256_AES128GCM_SHA256 / P-256

our %PROPOSAL_TYPE = (add => 1, update => 2, remove => 3);
my %PROPOSAL_NAME = reverse %PROPOSAL_TYPE;

our %CONTENT_TYPE = (application => 1, proposal => 2, commit => 3);
my %CONTENT_NAME = reverse %CONTENT_TYPE;

our %WIRE_FORMAT = (
    public_message => 1, private_message => 2, welcome => 3,
    group_info => 4, key_package => 5,
);

our %SENDER_TYPE = (
    member => 1, external => 2, new_member_commit => 3, new_member_proposal => 4,
);
my %SENDER_NAME = reverse %SENDER_TYPE;

our %CREDENTIAL_TYPE = (basic => 1, x509 => 2);

# ---------------------------------------------------------------- 署名 / ラベル

# SignContent = opaque label<V> || opaque content<V>
# label は "MLS 1.0 " + Label
sub sign_content {
    my ($label, $content) = @_;
    return tls_opaqueV("MLS 1.0 $label") . tls_opaqueV($content);
}

sub sign_with_label {
    my ($priv_hex, $label, $content) = @_;
    my $hash = sha256(sign_content($label, $content));
    my ($r, $s) = p256_sign($priv_hex, $hash);
    return _ecdsa_der(bytes_from_hex($r), bytes_from_hex($s));
}

sub verify_with_label {
    my ($pub_point, $label, $content, $sig) = @_;

    my $hash = sha256(sign_content($label, $content));
    my ($r_hex, $s_hex) = _parse_ecdsa_der($sig);
    return 0 unless defined $r_hex;
    return p256_verify($hash, $r_hex, $s_hex, $pub_point);
}

# EncryptContext = opaque label<V> || opaque context<V>
sub encrypt_context {
    my ($label, $context) = @_;
    return tls_opaqueV("MLS 1.0 $label") . tls_opaqueV($context // '');
}

# RefHash(label, value) = Hash(opaque label<V> || opaque value<V>)
sub ref_hash {
    my ($label, $value) = @_;
    return sha256(tls_opaqueV($label) . tls_opaqueV($value));
}

sub make_key_package_ref { return ref_hash('MLS 1.0 KeyPackage Reference', $_[0]) }
sub make_proposal_ref    { return ref_hash('MLS 1.0 Proposal Reference',  $_[0]) }

sub bytes_from_hex { return pack 'H*', $_[0] }

# ECDSA 署名の DER エンコード（ECDSA-Sig-Value）
sub _ecdsa_der {
    my ($r, $s) = @_;
    $r =~ s/^\x00+//;
    $s =~ s/^\x00+//;
    $r = "\x00" . $r if length($r) && ord($r) >= 0x80;
    $s = "\x00" . $s if length($s) && ord($s) >= 0x80;
    my $body = "\x02" . tls_u8(length $r) . $r . "\x02" . tls_u8(length $s) . $s;
    return "\x30" . tls_u8(length $body) . $body;
}

sub _parse_ecdsa_der {
    my ($der) = @_;
    return unless defined $der && length $der >= 8;
    return unless ord(substr($der, 0, 1)) == 0x30;

    my $pos = 1;
    my $len = ord substr($der, $pos++, 1);
    $len = (($len & 0x7f) << 8 | ord substr($der, $pos++, 1)) if $len & 0x80;

    return unless ord(substr($der, $pos, 1)) == 0x02;
    $pos++;
    my $rlen = ord substr($der, $pos++, 1);
    my $rb = substr($der, $pos, $rlen);
    $pos += $rlen;

    return unless ord(substr($der, $pos, 1)) == 0x02;
    $pos++;
    my $slen = ord substr($der, $pos++, 1);
    my $sb = substr($der, $pos, $slen);

    for ($rb, $sb) {
        s/^\x00+//;
        $_ = "\x00" x (32 - length $_) . $_ if length($_) < 32;
    }
    return (unpack('H*', $rb), unpack('H*', $sb));
}

# ---------------------------------------------------------------- Credential

# struct { CredentialType credential_type; select { basic: opaque identity<V> } }
sub encode_credential {
    my ($identity) = @_;
    return tls_u16(1) . tls_opaqueV($identity);
}

sub decode_credential {
    my ($r) = @_;
    my $type = $r->reader_u16;
    die "unsupported credential type $type\n" unless $type == 1;
    my $identity = $r->reader_opaqueV;
    return { type => $type, identity => $identity };
}

sub user_id_identity {
    my ($user_id) = @_;
    return pack 'Q>', $user_id;
}

sub identity_user_id {
    my ($identity) = @_;
    return unpack 'Q>', $identity if length($identity) == 8;
    return undef;
}

# ---------------------------------------------------------------- Extension

sub encode_extension {
    my ($type, $data) = @_;
    return tls_u16($type) . tls_opaqueV($data);
}

sub decode_extensions {
    my ($bytes) = @_;
    my @ext;
    my $r = Reader->new($bytes);
    while ($r->reader_remaining > 0) {
        my $type = $r->reader_u16;
        push @ext, { type => $type, data => $r->reader_opaqueV };
    }
    return \@ext;
}

sub encode_extensions {
    my ($exts) = @_;
    my $bytes = '';
    $bytes .= encode_extension($_->{type}, $_->{data} // '') for @$exts;
    return tls_opaqueV($bytes);
}

# ---------------------------------------------------------------- Capabilities

# 各フィールドは uint16 のベクタ（<V>）
sub encode_capabilities {
    my ($c) = @_;
    $c ||= {};

    my $versions    = $c->{versions}        // [MLS_VERSION];
    my $ciphers     = $c->{cipher_suites}   // [CIPHER_SUITE];
    my $extensions  = $c->{extensions}      // [];
    my $proposals   = $c->{proposals}       // [1, 3];    # add, remove
    my $credentials = $c->{credentials}     // [1];       # basic

    return tls_opaqueV(pack('n*', @$versions))
         . tls_opaqueV(pack('n*', @$ciphers))
         . tls_opaqueV(pack('n*', @$extensions))
         . tls_opaqueV(pack('n*', @$proposals))
         . tls_opaqueV(pack('n*', @$credentials));
}

sub decode_capabilities {
    my ($r) = @_;
    return {
        versions      => [ unpack 'n*', $r->reader_opaqueV ],
        cipher_suites => [ unpack 'n*', $r->reader_opaqueV ],
        extensions    => [ unpack 'n*', $r->reader_opaqueV ],
        proposals     => [ unpack 'n*', $r->reader_opaqueV ],
        credentials   => [ unpack 'n*', $r->reader_opaqueV ],
    };
}

# ---------------------------------------------------------------- LeafNode

# LeafNodeSource
use constant LEAF_SOURCE_KEY_PACKAGE => 1;
use constant LEAF_SOURCE_UPDATE      => 2;
use constant LEAF_SOURCE_COMMIT      => 3;

sub _leaf_common {
    my ($node) = @_;
    my $source = $node->{leaf_node_source} // LEAF_SOURCE_KEY_PACKAGE;
    my $out = tls_opaqueV($node->{encryption_key})
            . tls_opaqueV($node->{signature_key})
            . encode_credential($node->{credential}{identity})
            . encode_capabilities($node->{capabilities})
            . tls_u8($source);

    if ($source == LEAF_SOURCE_KEY_PACKAGE) {
        $out .= tls_u64($node->{lifetime}{not_before} // 0)
              . tls_u64($node->{lifetime}{not_after}  // ((1 << 63) - 1));
    } elsif ($source == LEAF_SOURCE_COMMIT) {
        $out .= tls_opaqueV($node->{parent_hash} // '');
    }
    $out .= encode_extensions($node->{extensions} // []);
    return $out;
}

sub leaf_node_tbs {
    my ($node) = @_;
    my $out = _leaf_common($node);
    my $source = $node->{leaf_node_source} // LEAF_SOURCE_KEY_PACKAGE;
    if ($source == LEAF_SOURCE_UPDATE || $source == LEAF_SOURCE_COMMIT) {
        $out .= tls_opaqueV($node->{group_id} // '')
              . tls_u32($node->{leaf_index} // 0);
    }
    return $out;
}

sub encode_leaf_node {
    my ($node) = @_;

    my $tbs = leaf_node_tbs($node);
    my $sig = $node->{signature};
    $sig = sign_with_label($node->{signing_key}, 'LeafNodeTBS', $tbs)
        unless defined $sig;

    return $tbs . tls_opaqueV($sig);
}

sub decode_leaf_node {
    my ($r) = @_;

    my $start = $r->{pos};
    my $enc   = $r->reader_opaqueV;
    my $sigk  = $r->reader_opaqueV;
    my $cred  = decode_credential($r);
    my $caps  = decode_capabilities($r);
    my $source = $r->reader_u8;

    my %node = (
        encryption_key   => $enc,
        signature_key    => $sigk,
        credential       => $cred,
        capabilities     => $caps,
        leaf_node_source => $source,
    );

    if ($source == LEAF_SOURCE_KEY_PACKAGE) {
        $node{lifetime} = { not_before => $r->reader_u64, not_after => $r->reader_u64 };
    } elsif ($source == LEAF_SOURCE_COMMIT) {
        $node{parent_hash} = $r->reader_opaqueV;
    }

    $node{extensions} = decode_extensions($r->reader_opaqueV);

    if ($source == LEAF_SOURCE_UPDATE || $source == LEAF_SOURCE_COMMIT) {
        $node{group_id}   = $r->reader_opaqueV;
        $node{leaf_index} = $r->reader_u32;
    }

    $node{tbs} = substr($r->{data}, $start, $r->{pos} - $start);
    $node{signature} = $r->reader_opaqueV;

    return \%node;
}

# ---------------------------------------------------------------- KeyPackage

sub key_package_tbs {
    my ($kp) = @_;
    return tls_u16($kp->{version} // MLS_VERSION)
         . tls_u16($kp->{cipher_suite} // CIPHER_SUITE)
         . tls_opaqueV($kp->{init_key})
         . encode_leaf_node($kp->{leaf_node})
         . encode_extensions($kp->{extensions} // []);
}

sub encode_key_package {
    my ($kp) = @_;

    my $tbs = key_package_tbs($kp);
    my $sig = $kp->{signature};
    $sig = sign_with_label($kp->{signing_key}, 'KeyPackageTBS', $tbs)
        unless defined $sig;

    return $tbs . tls_opaqueV($sig);
}

sub decode_key_package {
    my ($bytes) = @_;

    my $r = Reader->new($bytes);
    my $version = $r->reader_u16;
    my $suite   = $r->reader_u16;
    my $init    = $r->reader_opaqueV;
    my $leaf    = decode_leaf_node($r);
    my $exts    = decode_extensions($r->reader_opaqueV);
    my $sig     = $r->reader_opaqueV;

    return {
        version      => $version,
        cipher_suite => $suite,
        init_key     => $init,
        leaf_node    => $leaf,
        extensions   => $exts,
        signature    => $sig,
    };
}

sub verify_key_package {
    my ($kp) = @_;
    return 0 unless $kp->{version} == MLS_VERSION;
    return 0 unless $kp->{cipher_suite} == CIPHER_SUITE;

    my $pub = p256_uncompress($kp->{leaf_node}{signature_key});
    return 0 unless $pub;
    return verify_with_label($pub, 'KeyPackageTBS', key_package_tbs($kp), $kp->{signature});
}

# ---------------------------------------------------------------- GroupContext

sub encode_group_context {
    my ($ctx) = @_;
    return tls_u16($ctx->{version} // MLS_VERSION)
         . tls_u16($ctx->{cipher_suite} // CIPHER_SUITE)
         . tls_opaqueV($ctx->{group_id} // '')
         . tls_u64($ctx->{epoch} // 0)
         . tls_opaqueV($ctx->{tree_hash} // '')
         . tls_opaqueV($ctx->{confirmed_transcript_hash} // '')
         . encode_extensions($ctx->{extensions} // []);
}

sub decode_group_context {
    my ($bytes) = @_;
    my $r = Reader->new($bytes);
    return {
        version      => $r->reader_u16,
        cipher_suite => $r->reader_u16,
        group_id     => $r->reader_opaqueV,
        epoch        => $r->reader_u64,
        tree_hash    => $r->reader_opaqueV,
        confirmed_transcript_hash => $r->reader_opaqueV,
        extensions   => decode_extensions($r->reader_opaqueV),
    };
}

# ---------------------------------------------------------------- Sender

sub encode_sender {
    my ($sender) = @_;
    my $type = $sender->{type} // 'member';
    my $code = ref $type ? $type : $SENDER_TYPE{$type};
    my $out = tls_u8($code);

    if ($code == $SENDER_TYPE{member}) {
        $out .= tls_u32($sender->{leaf_index});
    } elsif ($code == $SENDER_TYPE{external}) {
        $out .= tls_u32($sender->{sender_index} // 0);
    }
    return $out;
}

sub decode_sender {
    my ($r) = @_;
    my $code = $r->reader_u8;
    my %s = (code => $code, type => $SENDER_NAME{$code} // $code);
    if ($code == $SENDER_TYPE{member}) {
        $s{leaf_index} = $r->reader_u32;
    } elsif ($code == $SENDER_TYPE{external}) {
        $s{sender_index} = $r->reader_u32;
    }
    return \%s;
}

# ---------------------------------------------------------------- Proposal

sub encode_proposal {
    my ($p) = @_;
    my $type = $p->{type};
    my $code = ref $type ? $type : $PROPOSAL_TYPE{$type};
    my $out  = tls_u16($code);

    if ($code == $PROPOSAL_TYPE{add}) {
        my $kp = $p->{key_package};
        $out .= ref $kp ? encode_key_package($kp) : $kp;
    } elsif ($code == $PROPOSAL_TYPE{update}) {
        $out .= encode_leaf_node($p->{leaf_node});
    } elsif ($code == $PROPOSAL_TYPE{remove}) {
        $out .= tls_u32($p->{removed});
    }
    return $out;
}

sub decode_proposal {
    my ($r) = @_;
    my $code = $r->reader_u16;
    my %p = (type => $PROPOSAL_NAME{$code} // $code, code => $code);

    if ($code == $PROPOSAL_TYPE{add}) {
        my $kp = decode_key_package_from_reader($r);
        $p{key_package} = $kp;
    } elsif ($code == $PROPOSAL_TYPE{update}) {
        $p{leaf_node} = decode_leaf_node($r);
    } elsif ($code == $PROPOSAL_TYPE{remove}) {
        $p{removed} = $r->reader_u32;
    }
    return \%p;
}

sub decode_key_package_from_reader {
    my ($r) = @_;
    my $version = $r->reader_u16;
    my $suite   = $r->reader_u16;
    my $init    = $r->reader_opaqueV;
    my $leaf    = decode_leaf_node($r);
    my $exts    = decode_extensions($r->reader_opaqueV);
    my $sig     = $r->reader_opaqueV;
    return {
        version => $version, cipher_suite => $suite, init_key => $init,
        leaf_node => $leaf, extensions => $exts, signature => $sig,
    };
}

# ---------------------------------------------------------------- Commit

# ProposalOrRefType: proposal=1, reference=2
sub encode_commit {
    my ($c) = @_;

    my $bytes = '';
    for my $p (@{ $c->{proposals} // [] }) {
        if (ref $p eq 'HASH' && exists $p->{ref}) {
            $bytes .= tls_u8(2) . tls_opaqueV($p->{ref});
        } else {
            $bytes .= tls_u8(1) . encode_proposal($p);
        }
    }

    my $out = tls_opaqueV($bytes);
    if ($c->{path}) {
        $out .= tls_u8(1) . encode_update_path($c->{path});
    } else {
        $out .= tls_u8(0);
    }
    return $out;
}

sub decode_commit {
    my ($r) = @_;

    my $prop_bytes = $r->reader_opaqueV;
    my @proposals;
    my $pr = Reader->new($prop_bytes);
    while ($pr->reader_remaining > 0) {
        my $kind = $pr->reader_u8;
        if ($kind == 1) {
            push @proposals, { kind => 1, proposal => decode_proposal($pr) };
        } elsif ($kind == 2) {
            push @proposals, { kind => 2, ref => $pr->reader_opaqueV };
        } else {
            die "invalid ProposalOrRefType $kind\n";
        }
    }

    my $has_path = $r->reader_u8;
    my $path = $has_path ? decode_update_path($r) : undef;

    return { proposals => \@proposals, path => $path };
}

# ---------------------------------------------------------------- UpdatePath

sub encode_parent_node {
    my ($n) = @_;
    return tls_opaqueV($n->{encryption_key})
         . tls_opaqueV($n->{parent_hash} // '')
         . tls_opaqueV($n->{unmerged_leaves} // '');
}

sub decode_parent_node {
    my ($r) = @_;
    return {
        encryption_key  => $r->reader_opaqueV,
        parent_hash     => $r->reader_opaqueV,
        unmerged_leaves => $r->reader_opaqueV,
    };
}

sub encode_update_path {
    my ($path) = @_;

    my $nodes = '';
    $nodes .= encode_parent_node($_) for @{ $path->{nodes} // [] };

    return encode_leaf_node($path->{leaf_node}) . tls_opaqueV($nodes);
}

sub decode_update_path {
    my ($r) = @_;

    my $leaf_node = decode_leaf_node($r);
    my $bytes = $r->reader_opaqueV;

    my @nodes;
    my $nr = Reader->new($bytes);
    while ($nr->reader_remaining > 0) {
        push @nodes, decode_parent_node($nr);
    }
    return { leaf_node => $leaf_node, nodes => \@nodes };
}

# ---------------------------------------------------------------- FramedContent

sub encode_framed_content {
    my ($fc) = @_;
    my $ct = $fc->{content_type};
    my $out = encode_sender($fc->{sender})
            . tls_opaqueV($fc->{authenticated_data} // '')
            . tls_u8($CONTENT_TYPE{$ct});

    if ($ct eq 'proposal') {
        $out .= encode_proposal($fc->{proposal});
    } elsif ($ct eq 'commit') {
        $out .= encode_commit($fc->{commit});
    } else {
        $out .= tls_opaqueV($fc->{application_data} // '');
    }
    return $out;
}

sub decode_framed_content {
    my ($r) = @_;

    my $sender = decode_sender($r);
    my $adata  = $r->reader_opaqueV;
    my $code   = $r->reader_u8;
    my $ctype  = $CONTENT_NAME{$code}
        or die "invalid ContentType $code\n";

    my %fc = (
        sender => $sender, authenticated_data => $adata,
        content_type => $ctype, code => $code,
    );

    if ($ctype eq 'proposal') {
        $fc{proposal} = decode_proposal($r);
    } elsif ($ctype eq 'commit') {
        $fc{commit} = decode_commit($r);
    } else {
        $fc{application_data} = $r->reader_opaqueV;
    }
    return \%fc;
}

# FramedContentTBS = version || wire_format || FramedContent || GroupContext?
sub framed_content_tbs {
    my ($fc, $context_bytes, $wire_format) = @_;
    my $out = tls_u16(MLS_VERSION)
            . tls_u8($wire_format // $WIRE_FORMAT{public_message})
            . encode_framed_content($fc);

    my $sender_type = $fc->{sender}{code} // $SENDER_TYPE{ $fc->{sender}{type} // 'member' };
    if ($sender_type == $SENDER_TYPE{member} || $sender_type == $SENDER_TYPE{new_member_commit}) {
        $out .= $context_bytes // '';
    }
    return $out;
}

# FramedContentAuthData: signature<V> + [confirmation_tag for commit]
sub encode_framed_content_auth_data {
    my ($auth, $content_type) = @_;
    my $out = tls_opaqueV($auth->{signature});
    if (($content_type // '') eq 'commit') {
        $out .= tls_opaqueV($auth->{confirmation_tag});
    }
    return $out;
}

sub decode_framed_content_auth_data {
    my ($r, $content_type) = @_;
    my %auth = (signature => $r->reader_opaqueV);
    if (($content_type // '') eq 'commit') {
        $auth{confirmation_tag} = $r->reader_opaqueV;
    }
    return \%auth;
}

# ---------------------------------------------------------------- PublicMessage

sub encode_public_message {
    my ($pm) = @_;
    my $ct = $pm->{content}{content_type};

    my $out = encode_framed_content($pm->{content})
            . encode_framed_content_auth_data({
                  signature        => $pm->{signature},
                  confirmation_tag => $pm->{confirmation_tag},
              }, $ct);

    my $sender_code = $pm->{content}{sender}{code}
        // $SENDER_TYPE{ $pm->{content}{sender}{type} // 'member' };
    if ($sender_code == $SENDER_TYPE{member}) {
        $out .= tls_opaqueV($pm->{membership_tag} // '');
    }
    return $out;
}

sub decode_public_message {
    my ($bytes) = @_;

    my $r = Reader->new($bytes);
    my $content = decode_framed_content($r);
    my $auth    = decode_framed_content_auth_data($r, $content->{content_type});

    my $sender_code = $content->{sender}{code};
    my $membership_tag;
    $membership_tag = $r->reader_opaqueV if $sender_code == $SENDER_TYPE{member};

    return {
        content          => $content,
        signature        => $auth->{signature},
        confirmation_tag => $auth->{confirmation_tag},
        membership_tag   => $membership_tag,
        rest             => $r->reader_rest,
    };
}

# MLSMessage = version || wire_format || body
sub encode_mls_message {
    my ($wire_format, $body) = @_;
    return tls_u16(MLS_VERSION) . tls_u16($wire_format) . $body;
}

sub decode_mls_message {
    my ($bytes) = @_;
    my ($version, $wire) = unpack 'nn', substr($bytes, 0, 4);
    return {
        version => $version,
        wire_format => $wire,
        body => substr($bytes, 4),
    };
}

# ---------------------------------------------------------------- Welcome / GroupInfo

# GroupSecrets = opaque joiner_secret<V> || optional<PathSecret> || PreSharedKeyID psks<V>
sub encode_group_secrets {
    my ($gs) = @_;

    my $out = tls_opaqueV($gs->{joiner_secret});

    if (defined $gs->{path_secret}) {
        $out .= tls_u8(1) . tls_opaqueV($gs->{path_secret});
    } else {
        $out .= tls_u8(0);
    }

    $out .= tls_opaqueV($gs->{psks} // '');
    return $out;
}

sub decode_group_secrets {
    my ($bytes) = @_;
    my $r = Reader->new($bytes);
    my $joiner = $r->reader_opaqueV;
    my $has_ps = $r->reader_u8;
    my $path   = $has_ps ? $r->reader_opaqueV : undef;
    my $psks   = $r->reader_opaqueV;
    return { joiner_secret => $joiner, path_secret => $path, psks => $psks };
}

# EncryptedGroupSecrets = KeyPackageRef new_member || HPKECiphertext
sub encode_encrypted_group_secrets {
    my ($s) = @_;
    return tls_opaqueV($s->{key_package_ref})
         . tls_opaqueV($s->{kem_output})
         . tls_opaqueV($s->{ciphertext});
}

sub decode_encrypted_group_secrets {
    my ($r) = @_;
    return {
        key_package_ref => $r->reader_opaqueV,
        kem_output      => $r->reader_opaqueV,
        ciphertext      => $r->reader_opaqueV,
    };
}

# Welcome = CipherSuite || EncryptedGroupSecrets secrets<V> || opaque encrypted_group_info<V>
sub encode_welcome {
    my ($w) = @_;

    my $secrets = '';
    $secrets .= encode_encrypted_group_secrets($_) for @{ $w->{secrets} // [] };

    return tls_u16($w->{cipher_suite} // CIPHER_SUITE)
         . tls_opaqueV($secrets)
         . tls_opaqueV($w->{encrypted_group_info});
}

sub decode_welcome {
    my ($bytes) = @_;
    my $r = Reader->new($bytes);
    my $suite = $r->reader_u16;
    my $sec_bytes = $r->reader_opaqueV;

    my @secrets;
    my $sr = Reader->new($sec_bytes);
    while ($sr->reader_remaining > 0) {
        push @secrets, decode_encrypted_group_secrets($sr);
    }
    return {
        cipher_suite => $suite,
        secrets => \@secrets,
        encrypted_group_info => $r->reader_opaqueV,
    };
}

# GroupInfoTBS = GroupContext || extensions<V> || confirmation_tag || uint32 signer
sub group_info_tbs {
    my ($gi) = @_;
    return $gi->{group_context}
         . encode_extensions($gi->{extensions} // [])
         . tls_opaqueV($gi->{confirmation_tag})
         . tls_u32($gi->{signer_index} // 0);
}

sub encode_group_info {
    my ($gi) = @_;

    my $tbs = group_info_tbs($gi);
    my $sig = $gi->{signature};
    $sig = sign_with_label($gi->{signing_key}, 'GroupInfoTBS', $tbs)
        unless defined $sig;

    return $tbs . tls_opaqueV($sig);
}

sub decode_group_info {
    my ($bytes) = @_;

    my $r = Reader->new($bytes);
    my $ctx_start = $r->{pos};
    my $ctx = decode_group_context_from_reader($r);
    my $ctx_bytes = substr($r->{data}, $ctx_start, $r->{pos} - $ctx_start);
    my $exts = decode_extensions($r->reader_opaqueV);
    my $tag  = $r->reader_opaqueV;
    my $signer = $r->reader_u32;
    my $sig  = $r->reader_opaqueV;

    return {
        group_context_bytes => $ctx_bytes,
        group_context       => $ctx,
        extensions          => $exts,
        confirmation_tag    => $tag,
        signer_index        => $signer,
        signature           => $sig,
    };
}

sub decode_group_context_from_reader {
    my ($r) = @_;
    return {
        version      => $r->reader_u16,
        cipher_suite => $r->reader_u16,
        group_id     => $r->reader_opaqueV,
        epoch        => $r->reader_u64,
        tree_hash    => $r->reader_opaqueV,
        confirmed_transcript_hash => $r->reader_opaqueV,
        extensions   => decode_extensions($r->reader_opaqueV),
    };
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::MLS - MLS 1.0（RFC 9420）のシリアライザ

=head1 DESCRIPTION

DAVE が必要とするサブセット。ciphersuite 2（P-256 + AES-128-GCM + SHA-256）。

長さフィールドは RFC 9420 §1.2 の可変長整数（C<< <V> >>）。1/2/4 バイトで、
先頭 2 bit が長さのバイト数-1 を表す。MLS のメッセージはすべてこの形式。

署名は SignWithLabel、暗号化は EncryptWithLabel で、どちらも
label と context を C<opaque xE<lt>VE<gt>> として前置する。

=cut
