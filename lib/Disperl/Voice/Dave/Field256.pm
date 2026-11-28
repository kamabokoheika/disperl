package Disperl::Voice::Dave::Field256;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';
use Config;
our @EXPORT_OK = qw(fe_from_bytes fe_to_bytes fe_from_int fe_add fe_sub fe_mul fe_sq
                    fe_inv fe_neg fe_is_zero fe_cmp fe_copy fe_p fe_reduce
                    mont_mul mont_sqr to_mont from_mont fe_mul_mont fe_inv_mont make_mont
                    limbs_to_bytes bytes_to_limbs);

# P-256 の素体演算（Pure Perl、core モジュールのみ、BigInt 不使用）。
#
# 表現: 26bit リム x 10 本の配列リファレンス（リトルエンディアン）。
# 乗算はモンゴメリ乗算（CIOS 法）。負のリムを出さずキャリーだけで還元できる。
#   p = 2^256 - 2^224 + 2^192 + 2^96 - 1

# 整数が 64bit 未満の Perl（32bit ビルド）では、展開した整数コードの代わりに
# 浮動小数点（2^53 まで厳密）で計算する経路を使う。DISPERL_FORCE_32BIT=1 で強制できる（テスト用）。
my $FAST = ($Config{ivsize} >= 8 && !$ENV{DISPERL_FORCE_32BIT}) ? 1 : 0;

my $BITS = 26;
my $S    = 10;
my $MASK = (1 << $BITS) - 1;

my @P = (67108863, 67108863, 67108863, 262143, 0, 0, 0, 1024, 67043328, 4194303);

# 2^260 mod p（キャリーを畳むのに使う）
my @C256 = (16, 0, 0, 62914560, 67108863, 67108863, 67108863, 67092479, 1048575, 0);

# モンゴメリ定数（R = 2^260）
my $N0 = 0x1;                  # -p^-1 mod 2^26
my @R2 = (768, 0, 66060288, 67108863, 67108859, 67108799,
          67108863, 66584575, 16777215, 1);
my @ONE = (1, (0) x 9);

sub fe_p { return [@P] }

# ---------------------------------------------------------------- バイト変換

sub bytes_to_limbs {
    my ($bytes) = @_;
    die "expected 32 bytes\n" unless defined $bytes && length($bytes) == 32;

    my @b16 = unpack 'v16', scalar reverse $bytes;
    my @l;
    for my $i (0 .. $S - 1) {
        my $lo = $i * $BITS;
        my $v  = 0;
        for my $b (0 .. $BITS - 1) {
            my $bit    = $lo + $b;
            my $limb16 = $bit >> 4;
            last if $limb16 > 15;
            my $off = $bit & 15;
            $v |= ((($b16[$limb16] >> $off) & 1) << $b);
        }
        $l[$i] = $v;
    }
    return \@l;
}

sub limbs_to_bytes {
    my ($limbs) = @_;
    my @b16 = (0) x 16;
    for my $i (0 .. $S - 1) {
        my $v  = $limbs->[$i] // 0;
        my $lo = $i * $BITS;
        for my $b (0 .. $BITS - 1) {
            next unless ($v >> $b) & 1;
            my $bit    = $lo + $b;
            my $limb16 = $bit >> 4;
            next if $limb16 > 15;
            my $off = $bit & 15;
            $b16[$limb16] |= (1 << $off);
        }
    }
    return scalar reverse pack 'v16', @b16;
}

sub fe_from_bytes { return bytes_to_limbs($_[0]) }

sub fe_from_int {
    my ($hex) = @_;
    $hex =~ s/^0x//;
    $hex = '0' x (64 - length $hex) . $hex if length $hex < 64;
    $hex = substr($hex, -64) if length $hex > 64;
    return bytes_to_limbs(pack 'H*', $hex);
}

sub fe_copy { return [ map { $_ // 0 } @{ $_[0] } ] }

# ---------------------------------------------------------------- 還元

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

sub _sub_p {
    my ($r) = @_;

    for (1 .. 3) {
        my $ge = 1;
        MATCH: for (my $i = $S - 1; $i >= 0; $i--) {
            if ($r->[$i] < $P[$i]) { $ge = 0; last MATCH }
            last MATCH if $r->[$i] > $P[$i];
        }
        last unless $ge;
        my $borrow = 0;
        for my $i (0 .. $S - 1) {
            my $x = $r->[$i] - $P[$i] - $borrow;
            if ($x < 0) { $x += 1 << $BITS; $borrow = 1 } else { $borrow = 0 }
            $r->[$i] = $x;
        }
    }
    return $r;
}

sub fe_reduce {
    my ($a) = @_;

    my @v = map { $_ // 0 } @$a;
    splice @v, $S if @v > $S;
    if (@v < $S) { $v[$_] = 0 for @v .. $S - 1 }

    $v[$_] += 2 * $P[$_] for 0 .. $S - 1;

    _carry(\@v);
    _sub_p(\@v);
    return \@v;
}

# ---------------------------------------------------------------- モンゴメリ乗算

# 32bit 整数の Perl 用。ビット演算は 2^32 を超える値を切り捨てるため使わず、
# 2 の冪の掛け算（厳密）と int() で繰り上がりを取る。各ステップの値は 2^53 未満。
# CIOS 法を展開したコードを生成する。2 乗は乗算で代用する。
sub _make_mont_float {
    my ($mod, $n0, $c256, $sub_mod, $carry) = @_;
    my @m = @$mod;
    my $INV  = '1.490116119384765625e-08';    # 2^-26（厳密）
    my $BASE = 1 << $BITS;

    my $code = 'sub { my ($pa, $pb) = @_;';
    $code .= 'my (' . join(',', map { "\$a$_" } 0 .. 9) . ') = @$pa;';
    $code .= 'my (' . join(',', map { "\$b$_" } 0 .. 9) . ') = @$pb;';
    $code .= 'my (' . join(',', map { "\$t$_" } 0 .. 10) . ') = (0) x 11; my ($x, $c, $m, $t11);';

    for my $i (0 .. 9) {
        $code .= "{ my \$bi = \$b$i; \$c = 0;";
        for my $j (0 .. 9) {
            $code .= "\$x = \$t$j + \$a$j*\$bi + \$c; \$c = int(\$x*$INV); \$t$j = \$x - \$c*$BASE;";
        }
        $code .= "\$x = \$t10 + \$c; \$c = int(\$x*$INV); \$t10 = \$x - \$c*$BASE; \$t11 = \$c;";

        $code .= "\$x = \$t0*$n0; \$m = \$x - int(\$x*$INV)*$BASE;";
        $code .= "\$x = \$t0 + \$m*$m[0]; \$c = int(\$x*$INV);";
        for my $j (1 .. 9) {
            my $pj = $m[$j] ? "+\$m*$m[$j]" : '';
            $code .= "\$x = \$t$j$pj + \$c; \$c = int(\$x*$INV); \$t" . ($j - 1) . " = \$x - \$c*$BASE;";
        }
        $code .= "\$x = \$t10 + \$c; \$c = int(\$x*$INV); \$t9 = \$x - \$c*$BASE; \$t10 = \$t11 + \$c; }";
    }

    $code .= 'my $r = [' . join(',', map { "\$t$_" } 0 .. 9) . '];';
    $code .= 'if ($t10) { $r->[$_] += $t10 * $c256->[$_] for 0 .. 9; $carry->($r); $sub_mod->($r) }';
    $code .= "elsif (\$t9 >= $m[9]) { \$sub_mod->(\$r) }";
    $code .= 'return $r; }';

    my $f = eval $code;
    die "make_mont(float): $@" unless $f;
    return ($f, sub { $f->($_[0], $_[0]) });
}

# 法ごとに展開した乗算 / 2 乗のコードを生成する（Scalar.pm も同じ生成器を使う）。
# 26bit x 26bit = 52bit の積を 10 個足しても 2^57 未満なので、列ごとに積を足し込み、
# キャリーは最後にまとめて処理する（integer 演算で動かす）。
sub make_mont {
    my ($mod, $n0, $c256, $sub_mod, $carry) = @_;
    return _make_mont_float(@_) unless $FAST;
    my @m = @$mod;

    my $build = sub {
        my ($sqr) = @_;
        my $code = 'use integer; sub { my ($pa' . ($sqr ? '' : ', $pb') . ') = @_;';
        $code .= 'my (' . join(',', map { "\$a$_" } 0 .. 9) . ') = @$pa;';
        $code .= 'my (' . join(',', map { "\$b$_" } 0 .. 9) . ') = @$pb;' unless $sqr;

        for my $k (0 .. 18) {
            my $e;
            if ($sqr) {
                my @x = map { "\$a$_*\$a" . ($k - $_) } grep { $k - $_ > $_ && $k - $_ <= 9 } 0 .. 9;
                $e = @x ? '2*(' . join('+', @x) . ')' : '';
                if (!($k & 1)) { my $h = $k / 2; $e .= ($e ? '+' : '') . "\$a$h*\$a$h" }
            } else {
                $e = join '+', map { "\$a$_*\$b" . ($k - $_) } grep { $k - $_ >= 0 && $k - $_ <= 9 } 0 .. 9;
            }
            $code .= "my \$c$k = $e;";
        }
        $code .= 'my $c19 = 0;';

        for my $i (0 .. 9) {
            my $mx = $n0 == 1 ? "\$c$i & $MASK" : "((\$c$i & $MASK) * $n0) & $MASK";
            $code .= "{ my \$m = $mx;";
            $code .= '$c' . ($i + 1) . " += (\$c$i + \$m*$m[0]) >> $BITS;";
            for my $j (1 .. 9) {
                next unless $m[$j];
                $code .= '$c' . ($i + $j) . " += \$m*$m[$j];";
            }
            $code .= '}';
        }

        for my $k (10 .. 18) {
            $code .= '$c' . ($k + 1) . " += \$c$k >> $BITS; \$c$k &= $MASK;";
        }
        $code .= "my \$t = \$c19 >> $BITS; \$c19 &= $MASK;";
        $code .= 'my $r = [' . join(',', map { "\$c$_" } 10 .. 19) . '];';
        $code .= 'if ($t) { $r->[$_] += $t * $c256->[$_] for 0 .. 9; $carry->($r); $sub_mod->($r) }';
        $code .= "elsif (\$c19 >= $m[9]) { \$sub_mod->(\$r) }";
        $code .= 'return $r; }';

        my $f = eval $code;
        die "make_mont: $@" unless $f;
        return $f;
    };
    return ($build->(0), $build->(1));
}

my ($MUL, $SQR) = make_mont(\@P, $N0, \@C256, \&_sub_p, \&_carry);

# mont_mul(a,b) = a*b*R^-1 mod p。結果は p 未満。
sub mont_mul { return $MUL->(@_) }
sub mont_sqr { return $SQR->($_[0]) }

sub to_mont   { return mont_mul($_[0], \@R2) }
sub from_mont { return mont_mul($_[0], \@ONE) }
sub fe_mul_mont { return $MUL->($_[0], $_[1]) }

# ---------------------------------------------------------------- 基本演算

sub fe_to_bytes {
    my ($a) = @_;

    my @v = map { $_ // 0 } @{ $a };
    splice @v, $S if @v > $S;
    if (@v < $S) { $v[$_] = 0 for @v .. $S - 1 }

    my $carry = 0;
    for my $i (0 .. $S - 1) {
        my $x = $v[$i] + $carry;
        $carry = $x >> $BITS;
        $v[$i] = $x - ($carry << $BITS);
    }
    return limbs_to_bytes([ @v[0 .. $S - 1] ]);
}

sub _fe_add_slow {
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
    _sub_p(\@r);
    return \@r;
}

# p 未満の正規化済みリム同士なら桁あふれしないので、展開した高速経路を使う。
my $FE_ADD = eval do {
    my $c = 'use integer; sub { my ($pa, $pb) = @_;';
    $c .= 'my (' . join(',', map { "\$a$_" } 0 .. 9) . ') = @$pa;';
    $c .= 'my (' . join(',', map { "\$b$_" } 0 .. 9) . ') = @$pb;';
    $c .= 'my $r0 = $a0 + $b0;';
    $c .= "my \$r$_ = \$a$_ + \$b$_ + (\$r" . ($_ - 1) . " >> $BITS); \$r" . ($_ - 1) . " &= $MASK;" for 1 .. 9;
    $c .= "if (\$r9 > $MASK) { return _fe_add_slow(\$pa, \$pb) }";
    $c .= 'my $r = [' . join(',', map { "\$r$_" } 0 .. 9) . '];';
    $c .= "_sub_p(\$r) if \$r9 >= $P[9]; return \$r; }";
    $c;
} or die "fe_add: $@";

my $FE_SUB = eval do {
    my $c = 'use integer; sub { my ($pa, $pb) = @_;';
    $c .= 'my (' . join(',', map { "\$a$_" } 0 .. 9) . ') = @$pa;';
    $c .= 'my (' . join(',', map { "\$b$_" } 0 .. 9) . ') = @$pb;';
    $c .= 'my $d0 = $a0 - $b0;';
    $c .= "my \$d$_ = \$a$_ - \$b$_ + (\$d" . ($_ - 1) . " >> $BITS); \$d" . ($_ - 1) . " &= $MASK;" for 1 .. 9;
    $c .= "my \$neg = \$d9 >> $BITS; \$d9 &= $MASK;";
    $c .= 'if ($neg) {';
    $c .= "\$d0 += $P[0];";
    $c .= "\$d$_ += $P[$_] + (\$d" . ($_ - 1) . " >> $BITS); \$d" . ($_ - 1) . " &= $MASK;" for 1 .. 9;
    $c .= "\$d9 &= $MASK; }";
    $c .= 'return [' . join(',', map { "\$d$_" } 0 .. 9) . ']; }';
    $c;
} or die "fe_sub: $@";

sub fe_add { return $FE_ADD->($_[0], $_[1]) }
sub fe_sub { return $FE_SUB->($_[0], $_[1]) }

sub fe_neg {
    my ($a) = @_;
    my @z = (0) x $S;
    return fe_sub(\@z, $a);
}

sub fe_mul {
    my ($a, $b) = @_;
    return $MUL->($a, to_mont($b));    # a * (bR) * R^-1 = a*b
}

sub fe_sq { return fe_mul($_[0], $_[0]) }

sub fe_is_zero {
    my ($a) = @_;
    my $r = fe_reduce($a);
    for my $v (@$r) { return 0 if $v; }
    return 1;
}

# 生のリム値をそのまま比較する（減算して 0 になる値同士を区別するため）
sub fe_cmp {
    my ($a, $b) = @_;
    for (my $i = $S - 1; $i >= 0; $i--) {
        my $x = $a->[$i] // 0;
        my $y = $b->[$i] // 0;
        return -1 if $x < $y;
        return 1  if $x > $y;
    }
    return 0;
}

# p-2 を 4bit ごとの桁（上位から）に分解した定数
my @P_MINUS_2_DIGITS = map { hex } split //,
    'ffffffff00000001000000000000000000000000fffffffffffffffffffffffd';

# モンゴメリ形式の逆元（モンゴメリ形式のまま返す）。4bit 窓。
sub fe_inv_mont {
    my ($a_mont) = @_;

    my @tbl = (undef, $a_mont);
    $tbl[$_] = $MUL->($tbl[$_ - 1], $a_mont) for 2 .. 15;

    my $r;
    for my $d (@P_MINUS_2_DIGITS) {
        if (defined $r) {
            $r = $SQR->($r) for 1 .. 4;
            $r = $MUL->($r, $tbl[$d]) if $d;
        } elsif ($d) {
            $r = $tbl[$d];
        }
    }
    return $r;
}

# 通常形式の逆元
sub fe_inv {
    my ($a) = @_;
    return [ map { 0 } 0 .. $S - 1 ] if fe_is_zero($a);
    return from_mont(fe_inv_mont(to_mont(fe_reduce($a))));
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::Field256 - P-256 の素体演算（Pure Perl）

=head1 DESCRIPTION

26bit リム 10 本で 256bit を表現する。乗算はモンゴメリ乗算（CIOS 法）。
外部モジュールは使わない（core のみ）。BigInt も使わない。

=cut
