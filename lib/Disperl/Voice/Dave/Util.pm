package Disperl::Voice::Dave::Util;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';
our @EXPORT_OK = qw(uleb128_encode uleb128_decode encode_uint16 decode_uint16
                    encode_uint64 decode_uint64 xor_bytes hexd random_bytes);

# 旧名（typo）も残しておく
sub uleB128_decode { goto &uleb128_decode }

# ULEB128（unsigned little endian base 128）。DAVE プロトコルの nonce と
# unencrypted ranges で使う（dave-protocol.md: ULEB128 Encoding）。
sub uleb128_encode {
    my ($value) = @_;
    my $out = '';
    while ($value >= 0x80) {
        $out .= chr(0x80 | ($value & 0x7F));
        $value >>= 7;
    }
    $out .= chr($value);
    return $out;
}

# ($value, $bytes_consumed) を返す
sub uleb128_decode {
    my ($buf, $offset) = @_;
    $offset //= 0;
    my $value = 0;
    my $shift = 0;
    my $len   = 0;
    while (1) {
        die "ULEB128: truncated input\n" if $offset + $len >= length($buf);
        my $b = ord(substr($buf, $offset + $len, 1));
        $value |= ($b & 0x7F) << $shift;
        $len++;
        last if ($b & 0x80) == 0;
        $shift += 7;
        die "ULEB128: too long\n" if $shift > 28;
    }
    return ($value, $len);
}

sub encode_uint16 { pack 'n', $_[0] }
sub decode_uint16 { unpack 'n', substr($_[0], 0, 2) }
sub encode_uint64 { pack 'Q>', $_[0] }
sub decode_uint64 { unpack 'Q>', substr($_[0], 0, 8) }

sub xor_bytes {
    my ($a, $b) = @_;
    return $a ^ $b;
}

sub hexd { pack 'H*', $_[0] }

# 乱数。/dev/urandom を使えない環境（Windows 等）でも動くように:
#   1. /dev/urandom（UNIX 系、一度開いておく）
#   2. Crypt::URandom（入っていれば）
#   3. rand + 時刻 + PID を SHA-256 に通したフォールバック
my $URANDOM;
my $URANDOM_TRIED = 0;

sub random_bytes {
    my ($n) = @_;

    if (!$URANDOM_TRIED) {
        $URANDOM_TRIED = 1;
        $URANDOM = undef;
        if (open my $fh, '<:raw', '/dev/urandom') {
            $URANDOM = $fh;
        }
    }
    if ($URANDOM) {
        my $buf = '';
        while (length($buf) < $n) {
            my $r = sysread($URANDOM, my $c, $n - length($buf));
            last unless defined $r && $r > 0;
            $buf .= $c;
        }
        return $buf if length($buf) >= $n;
    }

    if (eval { require Crypt::URandom; 1 }) {
        my $bytes = eval { Crypt::URandom::urandom($n) };
        return $bytes if defined $bytes && length($bytes) >= $n;
    }

    my $bytes = '';
    my $i = 0;
    while (length($bytes) < $n) {
        require Digest::SHA;
        $bytes .= Digest::SHA::sha256(join '|',
            ++$i, time(), $$, rand(), int(rand(1_000_000_000)),
            map { rand() } 1 .. 8,
        );
    }
    return substr($bytes, 0, $n);
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::Util - ULEB128 などのバイトユーティリティ

=cut
