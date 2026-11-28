package Disperl::Voice::Dave::Hpke;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';
use Digest::SHA qw(hmac_sha256);
use Disperl::Voice::Dave::Hkdf qw(hkdf_extract hkdf_expand);
use Disperl::Voice::Dave::P256 qw(p256_pubkey p256_ecdh p256_serialize p256_uncompress
                                  p256_valid_public p256_keygen os2ip_mod_n);
use Disperl::Voice::Dave::AesGcm qw(aes128_gcm_encrypt_oneshot aes128_gcm_decrypt_oneshot);

our @EXPORT_OK = qw(hpke_seal hpke_open hpke_export hpke_context hpke_encap hpke_decap
                    hpke_derive_keypair
                    hpke_labeled_extract hpke_labeled_expand);

# HPKE（RFC 9180）base mode。
# DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM（MLS ciphersuite 2 相当）。

my $KEM_ID  = 0x0010;
my $KDF_ID  = 0x0001;
my $AEAD_ID = 0x0001;
my $N_SECRET = 32;
my $N_K      = 16;
my $N_N      = 12;
my $N_H      = 32;

# 毎回組み立てない定数
my $KEM_SUITE_ID = "KEM" . pack('n', $KEM_ID);
my $SUITE_ID     = "HPKE" . pack('n', $KEM_ID) . pack('n', $KDF_ID) . pack('n', $AEAD_ID);
my $ZEROS_H      = "\x00" x $N_H;

sub hpke_labeled_extract {
    my ($suite_id, $salt, $label, $ikm) = @_;
    my $labeled_ikm = "HPKE-v1" . $suite_id . $label . $ikm;
    return hkdf_extract($salt, $labeled_ikm);
}

sub hpke_labeled_expand {
    my ($suite_id, $prk, $label, $info, $len) = @_;
    $info = '' unless defined $info;
    my $labeled_info = pack('n', $len) . "HPKE-v1" . $suite_id . $label . $info;
    return hkdf_expand($prk, $labeled_info, $len);
}

# DHKEM: DeriveKeyPair（RFC 9180 §7.1.3）
sub hpke_derive_keypair {
    my ($ikm) = @_;
    my $dkp_prk = hpke_labeled_extract($KEM_SUITE_ID, $ZEROS_H, 'dkp_prk', $ikm);

    for my $counter (0 .. 254) {
        my $candidate = hpke_labeled_expand($KEM_SUITE_ID, $dkp_prk, 'candidate', pack('C', $counter), 32);
        my $sk = os2ip_mod_n($candidate);
        next unless defined $sk;
        next if $sk !~ /[1-9a-f]/;
        return $sk;
    }
    die "DeriveKeyPair failed\n";
}

# DHKEM: encap / decap
sub _extract_and_expand {
    my ($dh, $kem_context) = @_;
    my $prk = hpke_labeled_extract($KEM_SUITE_ID, $ZEROS_H, 'eae_prk', $dh);
    return hpke_labeled_expand($KEM_SUITE_ID, $prk, 'shared_secret', $kem_context, $N_SECRET);
}

sub hpke_encap {
    my ($pkr_point, $sk_e) = @_;

    # $sk_e は 16 進文字列。省略時はランダムなエフェメラル鍵。
    $sk_e = p256_keygen() unless defined $sk_e;
    my $pk_e = p256_pubkey($sk_e);
    my $enc  = p256_serialize($pk_e);

    my $pkrm = p256_serialize($pkr_point);
    my $dh   = p256_ecdh($sk_e, $pkr_point);
    my $shared_secret = _extract_and_expand($dh, $enc . $pkrm);
    return ($shared_secret, $enc);
}

sub hpke_decap {
    my ($enc, $skr_hex, $pkr_point) = @_;
    my $pk_e  = p256_uncompress($enc);
    die "invalid public key\n" unless p256_valid_public($pk_e);
    my $pkrm  = p256_serialize($pkr_point);
    my $dh    = p256_ecdh($skr_hex, $pk_e);
    my $shared_secret = _extract_and_expand($dh, $enc . $pkrm);
    return $shared_secret;
}

# キースケジュール（base mode）
my $PSK_ID_HASH = hpke_labeled_extract($SUITE_ID, $ZEROS_H, 'psk_id_hash', '');
my %INFO_CACHE;    # info -> ks_context（MLS は同じ info を繰り返し使う）

sub _ks_context {
    my ($info) = @_;
    return $INFO_CACHE{$info} //= do {
        my $info_hash = hpke_labeled_extract($SUITE_ID, $ZEROS_H, 'info_hash', $info);
        "\x00" . $PSK_ID_HASH . $info_hash;    # mode 0 (base)
    };
}

sub hpke_context {
    my ($shared_secret, $info) = @_;
    $info = '' unless defined $info;

    my $ks_context = _ks_context($info);
    my $secret = hpke_labeled_extract($SUITE_ID, $shared_secret, 'secret', '');

    return {
        key    => hpke_labeled_expand($SUITE_ID, $secret, 'key',        $ks_context, $N_K),
        nonce  => hpke_labeled_expand($SUITE_ID, $secret, 'base_nonce', $ks_context, $N_N),
        export => hpke_labeled_expand($SUITE_ID, $secret, 'exp',        $ks_context, $N_H),
        seq    => 0,
    };
}

sub _compute_nonce {
    my ($ctx) = @_;
    my $seq_bytes = pack('N', $ctx->{seq} & 0xffffffff);
    my $nonce = "\x00" x 8 . $seq_bytes;
    return $ctx->{nonce} ^ $nonce;
}

sub hpke_seal {
    my ($pkr_point, $plaintext, $info, $aad) = @_;
    $aad = '' unless defined $aad;

    my ($shared_secret, $enc) = hpke_encap($pkr_point);
    my $ctx = hpke_context($shared_secret, $info);
    my ($ct, $tag) = aes128_gcm_encrypt_oneshot($ctx->{key}, _compute_nonce($ctx), $plaintext, $aad);
    return ($enc, $ct . $tag);
}

sub hpke_open {
    my ($enc, $skr_hex, $pkr_point, $ct_and_tag, $info, $aad) = @_;
    $aad = '' unless defined $aad;

    my $shared_secret = hpke_decap($enc, $skr_hex, $pkr_point);
    my $ctx = hpke_context($shared_secret, $info);
    die "ciphertext too short\n" if length($ct_and_tag) < 16;
    my $ct  = substr($ct_and_tag, 0, length($ct_and_tag) - 16);
    my $tag = substr($ct_and_tag, -16);
    return aes128_gcm_decrypt_oneshot($ctx->{key}, _compute_nonce($ctx), $ct, $aad, $tag);
}

# Export（RFC 9180 §5.3）。exporter_secret は hpke_context と同じ経路で導出する。
sub hpke_export {
    my ($shared_secret, $exporter_context, $len, $info) = @_;
    my $exporter_secret = hpke_context($shared_secret, $info)->{export};
    return hpke_labeled_expand($SUITE_ID, $exporter_secret, 'sec', $exporter_context // '', $len);
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::Hpke - HPKE（RFC 9180）base mode

=head1 SYNOPSIS

    use Disperl::Voice::Dave::Hpke;

    my ($enc, $ct) = hpke_seal($pub_point, $pt, $info, $aad);
    my $pt = hpke_open($enc, $sk_hex, $pub_point, $ct, $info, $aad);

=head1 DESCRIPTION

DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM。
RFC 9180 A.3 のテストベクタで検証（t/dave_crypto.t）。

=cut
