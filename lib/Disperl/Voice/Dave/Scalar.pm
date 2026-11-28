package Disperl::Voice::Dave::Scalar;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';
use Disperl::Voice::Dave::Field256 ();
use Disperl::Voice::Dave::Util qw(random_bytes);
our @EXPORT_OK = qw(sc_from_hex sc_to_hex sc_add sc_sub sc_mul sc_inv sc_is_zero
                    sc_cmp sc_reduce sc_n_hex sc_random sc_from_bytes sc_to_bytes
                    sc_random_bytes);

# P-256 の群の位数 n を法とする演算（Pure Perl、BigInt 不使用）。
# Field256 と同じ 26bit リム + モンゴメリ乗算（CIOS）だが、法が n 用。

my $BITS = 26;
my $S    = 10;
my $MASK = (1 << $BITS) - 1;

my @N = (
         6497617, 41070783, 32001851, 45522014, 62711546,
         67108863, 67108863, 1023, 67043328, 4194303,
);

my @C256 = (
         30255856, 13956110, 24841286, 9845272, 3248213,
         1, 0, 67092480, 1048575, 0,
);

my $N0 = 0x200bc4f;
my @R2 = (
         40747962, 24314746, 64528516, 6596633, 22376891,
         50009688, 52662966, 8325398, 22665558, 3689317,
);
my @ONE = (1, (0) x 9);

sub sc_n_hex { return 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551' }

sub _carry {
    my ($r) = @_;
    for my $round (1 .. 4) {
        my $carry = 0;
        for my $i (0 .. $S - 1) {
            my $x = $r->[$i] + $carry;
            $carry = $x >> $BITS;
            $r->[$i] = $x - ($carry << $BITS);
        }
        last unless $carry;
        $r->[$_] += $carry * $C256[$_] for 0 .. $S - 1;
    }
    return $r;
}

sub _sub_n {
    my ($r) = @_;
    for (1 .. 3) {
        my $ge = 1;
        MATCH: for (my $i = $S - 1; $i >= 0; $i--) {
            if ($r->[$i] < $N[$i]) { $ge = 0; last MATCH }
            last MATCH if $r->[$i] > $N[$i];
        }
        last unless $ge;
        my $borrow = 0;
        for my $i (0 .. $S - 1) {
            my $x = $r->[$i] - $N[$i] - $borrow;
            if ($x < 0) { $x += 1 << $BITS; $borrow = 1 } else { $borrow = 0 }
            $r->[$i] = $x;
        }
    }
    return $r;
}

sub sc_from_bytes {
    my ($bytes) = @_;
    return Disperl::Voice::Dave::Field256::bytes_to_limbs($bytes);
}

sub sc_to_bytes {
    my ($a) = @_;
    my @v = map { $_ // 0 } @$a;
    splice @v, $S if @v > $S;
    if (@v < $S) { $v[$_] = 0 for @v .. $S - 1 }
    my $carry = 0;
    for my $i (0 .. $S - 1) {
        my $x = $v[$i] + $carry;
        $carry = $x >> $BITS;
        $v[$i] = $x - ($carry << $BITS);
    }
    return Disperl::Voice::Dave::Field256::limbs_to_bytes([ @v[0 .. $S - 1] ]);
}

sub sc_from_hex {
    my ($hex) = @_;
    $hex =~ s/^0x//;
    $hex = '0' x (64 - length $hex) . $hex if length $hex < 64;
    $hex = substr($hex, -64) if length $hex > 64;
    return sc_from_bytes(pack 'H*', $hex);
}

sub sc_to_hex { return unpack 'H*', sc_to_bytes($_[0]) }

sub sc_reduce {
    my ($a) = @_;
    my @v = map { $_ // 0 } @$a;
    splice @v, $S if @v > $S;
    if (@v < $S) { $v[$_] = 0 for @v .. $S - 1 }
    $v[$_] += 2 * $N[$_] for 0 .. $S - 1;
    _carry(\@v);
    _sub_n(\@v);
    return \@v;
}

# Field256 と同じ生成器で n 用の展開コードを作る。
my ($MUL_N, $SQR_N) = Disperl::Voice::Dave::Field256::make_mont(\@N, $N0, \@C256, \&_sub_n, \&_carry);

sub mont_mul_n { return $MUL_N->($_[0], $_[1]) }

sub to_mont_n   { return mont_mul_n($_[0], \@R2) }
sub from_mont_n { return mont_mul_n($_[0], \@ONE) }

# mont_mul_n(a, bR) = a*b なので、片側だけ変換すれば足りる（乗算 2 回）。
sub sc_mul {
    my ($a, $b) = @_;
    return mont_mul_n($a, to_mont_n($b));
}

sub sc_add {
    my ($a, $b) = @_;
    my @r;
    my $c = 0;
    for my $i (0 .. $S - 1) {
        my $x = $a->[$i] + $b->[$i] + $c;
        $r[$i] = $x & $MASK;
        $c = $x >> $BITS;
    }
    for (1 .. 2) {
        last unless $c;
        my $c2 = 0;
        for my $i (0 .. $S - 1) {
            my $x = $r[$i] + $c * $C256[$i] + $c2;
            $r[$i] = $x & $MASK;
            $c2 = $x >> $BITS;
        }
        $c = $c2;
    }
    _sub_n(\@r);
    return \@r;
}

sub sc_sub {
    my ($a, $b) = @_;
    my @r;
    my $borrow = 0;
    for my $i (0 .. $S - 1) {
        my $x = $a->[$i] - $b->[$i] - $borrow;
        if ($x < 0) { $x += 1 << $BITS; $borrow = 1 } else { $borrow = 0 }
        $r[$i] = $x;
    }
    if ($borrow) {
        my $c = 0;
        for my $i (0 .. $S - 1) {
            my $x = $r[$i] + $N[$i] + $c;
            $r[$i] = $x & $MASK;
            $c = $x >> $BITS;
        }
    }
    return \@r;
}

sub sc_is_zero {
    my $r = sc_reduce($_[0]);
    for my $v (@$r) { return 0 if $v }
    return 1;
}

# 生のリム値をそのまま比較する（減算して 0 になる値同士を区別するため）
sub sc_cmp {
    my ($a, $b) = @_;
    for (my $i = $S - 1; $i >= 0; $i--) {
        my $x = $a->[$i] // 0;
        my $y = $b->[$i] // 0;
        return -1 if $x < $y;
        return 1  if $x > $y;
    }
    return 0;
}

# n-2 を 4bit ごとの桁（上位から）に分解。定数なので一度だけ計算する。
my @N_MINUS_2_DIGITS = do {
    my $hex = sc_n_hex();
    my $v = hex(substr($hex, -2)) - 2;    # 下位 1 バイトは 0x51 なので借りは出ない
    $hex = substr($hex, 0, -2) . sprintf('%02x', $v);
    map { hex } split //, $hex;
};

# モンゴメリ形式のまま 4bit 窓でべき乗する（乗算は約 340 回、各 1 回の mont_mul_n）。
sub sc_inv {
    my ($a) = @_;
    my $base = to_mont_n(sc_reduce($a));
    my @tbl = (undef, $base);
    $tbl[$_] = mont_mul_n($tbl[$_ - 1], $base) for 2 .. 15;

    my $r;
    for my $d (@N_MINUS_2_DIGITS) {
        if (defined $r) {
            $r = $SQR_N->($r) for 1 .. 4;
            $r = mont_mul_n($r, $tbl[$d]) if $d;
        } elsif ($d) {
            $r = $tbl[$d];
        }
    }
    return from_mont_n($r);
}

# 乱数を $n バイト。3 モジュールで共通に使う。
sub sc_random_bytes {
    my ($n) = @_;
    return random_bytes($n);
}

sub sc_random {
    my $r = sc_from_bytes(sc_random_bytes(32));
    _sub_n($r);
    return $r;
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::Scalar - P-256 の位数 n を法とする演算

=head1 DESCRIPTION

ECDSA の r, s, k^-1 計算に使う。Pure Perl（BigInt 不使用）。

=cut
