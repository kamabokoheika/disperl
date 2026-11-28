package Disperl::Voice::Dave::Hkdf;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';
use Digest::SHA qw(hmac_sha256 sha256);

our @EXPORT_OK = qw(hkdf_extract hkdf_expand expand_with_label derive_secret
                    mls_exporter);

# HKDF-SHA256（MLS ciphersuite 2 の KDF）

sub hkdf_extract {
    my ($salt, $ikm) = @_;
    $salt = "\x00" x 32 unless defined $salt && length $salt;
    return hmac_sha256($ikm, $salt);
}

sub hkdf_expand {
    my ($prk, $info, $len) = @_;
    $info = '' unless defined $info;

    my $out  = '';
    my $t    = '';
    my $i    = 1;
    while (length($out) < $len) {
        $t = hmac_sha256($t . $info . chr($i), $prk);
        $out .= $t;
        $i++;
    }
    return substr($out, 0, $len);
}

# MLS の ExpandWithLabel（RFC 9420 §8）。
#   KDFLabel = uint16be(length) || opaque label<V> || opaque context<V>
#   label = "MLS 1.0 " + Label
# mlspp では label / context の長さヘッダは 1 バイト（uint8）。
sub expand_with_label {
    my ($secret, $label, $context, $length) = @_;
    $context = '' unless defined $context;

    my $mls_label = "MLS 1.0 " . $label;
    my $kdf_label = pack('n', $length)
        . chr(length $mls_label) . $mls_label
        . chr(length $context) . $context;

    return hkdf_expand($secret, $kdf_label, $length);
}

sub derive_secret {
    my ($secret, $label) = @_;
    return expand_with_label($secret, $label, '', 32);
}

# MLS-Exporter（RFC 9420 §8.5）
#   MLS-Exporter(L, C, Len) = ExpandWithLabel(DeriveSecret(exporter_secret, L), "exported", Hash(C), Len)
sub mls_exporter {
    my ($exporter_secret, $label, $context, $length) = @_;
    my $derived = derive_secret($exporter_secret, $label);
    return expand_with_label($derived, 'exported', sha256($context // ''), $length);
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::Hkdf - HKDF-SHA256 と MLS のラベル付き展開

=head1 DESCRIPTION

MLS ciphersuite 2 の KDF。ExpandWithLabel / DeriveSecret / MLS-Exporter を含む。

=cut
