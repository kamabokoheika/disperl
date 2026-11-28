package Disperl::Voice::Dave::TLS;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';
our @EXPORT_OK = qw(tls_u8 tls_u16 tls_u32 tls_u64 tls_opaque8 tls_opaque16
                    tls_opaque32 tls_vec8 tls_vec16 tls_vec32
                    tls_varint tls_opaqueV
                    Reader reader_u8 reader_u16 reader_u32 reader_u64
                    reader_opaque8 reader_opaque16 reader_opaque32
                    reader_vec8 reader_vec16 reader_vec32 reader_remaining
                    reader_varint reader_opaqueV);

# RFC 8446 / RFC 9420 の TLS presentation language（サブセット）。
# MLS のメッセージはすべてバイト列でやり取りするので、必要な型だけ用意する。

sub tls_u8  { return pack 'C',  $_[0] & 0xff }
sub tls_u16 { return pack 'n',  $_[0] & 0xffff }
sub tls_u32 { return pack 'N',  $_[0] & 0xffffffff }
sub tls_u64 { return pack 'Q>', $_[0] & ~0 }

# opaque x<V>: RFC 9420 §1.2 の可変長整数（QUIC varint 風）。
# 先頭 2 bit が長さのバイト数-1 を表し、最小バイト数で符号化する。
sub tls_varint {
    my ($n) = @_;
    $n = 0 unless defined $n;
    die "varint too large: $n\n" if $n > 1_073_741_823;
    return pack 'C', $n if $n < 64;
    return pack 'n', 0x4000 | $n if $n < 16384;
    return pack 'N', 0x80000000 | $n;
}

# opaque x<V> は長さヘッダ + 本体
sub tls_opaque8  { my $b = $_[0] // ''; return tls_u8(length $b)  . $b }
sub tls_opaque16 { my $b = $_[0] // ''; return tls_u16(length $b) . $b }
sub tls_opaque32 { my $b = $_[0] // ''; return tls_u32(length $b) . $b }

# ベクタ（要素を連結したものに長さヘッダを付ける）
sub tls_vec8  { return tls_opaque8($_[0]) }
sub tls_vec16 { return tls_opaque16($_[0]) }
sub tls_vec32 { return tls_opaque32($_[0]) }

# opaque x<V> / T x<V>
sub tls_opaqueV {
    my $b = $_[0] // '';
    return tls_varint(length $b) . $b;
}

# ---------------------------------------------------------------- Reader

sub new {
    my ($class, $data) = @_;
    $class = __PACKAGE__ unless defined $class && !ref $class;
    return bless { data => $data // '', pos => 0 }, $class;
}

sub Reader { return __PACKAGE__->new($_[1]) }

sub reader_remaining { return length($_[0]->{data}) - $_[0]->{pos} }

sub _take {
    my ($self, $n) = @_;
    die "TLS: truncated (need $n bytes, have " . $self->reader_remaining . ")\n"
        if $n < 0 || $self->{pos} + $n > length $self->{data};
    my $out = substr($self->{data}, $self->{pos}, $n);
    $self->{pos} += $n;
    return $out;
}

sub reader_u8  { return unpack 'C',  $_[0]->_take(1) }
sub reader_u16 { return unpack 'n',  $_[0]->_take(2) }
sub reader_u32 { return unpack 'N',  $_[0]->_take(4) }
sub reader_u64 { return unpack 'Q>', $_[0]->_take(8) }

sub reader_opaque8  { my $n = $_[0]->reader_u8;  return $_[0]->_take($n) }
sub reader_opaque16 { my $n = $_[0]->reader_u16; return $_[0]->_take($n) }
sub reader_opaque32 { my $n = $_[0]->reader_u32; return $_[0]->_take($n) }

sub reader_vec8  { return $_[0]->reader_opaque8 }
sub reader_vec16 { return $_[0]->reader_opaque16 }
sub reader_vec32 { return $_[0]->reader_opaque32 }

sub reader_varint {
    my ($self) = @_;
    my $b0 = ord $self->_take(1);
    my $len = 1 << ($b0 >> 6);
    return $b0 if $len == 1;                      # 下位 6 bit がそのまま値
    return unpack('n', pack('C', $b0) . $self->_take(1)) & 0x3fff if $len == 2;
    return unpack('N', pack('C', $b0) . $self->_take(3)) & 0x3fffffff;
}

sub reader_opaqueV {
    my ($self) = @_;
    my $n = $self->reader_varint;
    return $self->_take($n);
}

# 残り全部
sub reader_rest {
    my ($self) = @_;
    return $self->_take($self->reader_remaining);
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::TLS - TLS presentation language の読み書き

=head1 SYNOPSIS

    use Disperl::Voice::Dave::TLS qw(tls_u16 tls_opaque16 Reader);

    my $bytes = tls_u16(1) . tls_opaque16($data);
    my $r = Reader->new($bytes);
    my $v = $r->reader_u16;
    my $d = $r->reader_opaque16;

=cut
