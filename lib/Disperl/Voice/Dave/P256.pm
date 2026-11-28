package Disperl::Voice::Dave::P256;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';
use Digest::SHA qw(sha256);
use Disperl::Voice::Dave::Util qw(random_bytes);

use Disperl::Voice::Dave::Field256 qw(
    fe_from_int fe_to_bytes fe_add fe_sub fe_mul fe_sq fe_inv fe_neg fe_is_zero fe_cmp
    mont_mul to_mont from_mont fe_mul_mont fe_p bytes_to_limbs
);
use Disperl::Voice::Dave::Scalar qw(
    sc_from_hex sc_to_hex sc_add sc_sub sc_mul sc_inv sc_is_zero sc_cmp sc_reduce
    sc_random sc_n_hex sc_from_bytes
);

our @EXPORT_OK = qw(p256_keygen p256_pubkey p256_ecdh p256_sign p256_verify
                    p256_serialize p256_uncompress p256_valid_public os2ip_mod_n
                    fe_to_bytes);

# NIST P-256（secp256r1）。MLS ciphersuite 2 の KEM / 署名用。
# 体演算は Disperl::Voice::Dave::Field256（Pure Perl、BigInt 不使用）。
# 座標はモンゴメリ形式で保持し、入出力で変換する。

my $GX = fe_from_int('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296');
my $GY = fe_from_int('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5');

# 曲線: y^2 = x^3 - 3x + b
my $B = fe_from_int('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');
my $A_MONT = fe_neg(to_mont(fe_from_int('3')));    # a = -3（モンゴメリ形式）

# 群の位数 n（16 進）
my $N_HEX = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';

# ---------------------------------------------------------------- 点演算（モンゴメリ形式）

# Jacobian: [X, Y, Z]（すべてモンゴメリ形式）。無限遠点は undef。
# アフィン座標は (X/Z^2, Y/Z^3)。

sub _jac_double {
    my ($p) = @_;
    return undef unless defined $p;
    my ($x, $y, $z) = @$p;
    return undef if fe_is_zero($y);

    my $y2 = fe_mul_mont($y, $y);          # Y^2
    my $z2 = fe_mul_mont($z, $z);          # Z^2
    my $z4 = fe_mul_mont($z2, $z2);        # Z^4

    # M = 3(X^2 - Z^4)  （a = -3 のとき）
    my $x2 = fe_mul_mont($x, $x);
    my $m  = fe_mul_mont(fe_sub($x2, $z4), to_mont(fe_from_int('3')));

    my $s  = fe_mul_mont(to_mont(fe_from_int('4')), fe_mul_mont($x, $y2));
    my $x3 = fe_sub(fe_mul_mont($m, $m), fe_add($s, $s));
    my $y3 = fe_sub(fe_mul_mont($m, fe_sub($s, $x3)),
                    fe_mul_mont(to_mont(fe_from_int('8')), fe_mul_mont($y2, $y2)));
    my $z3 = fe_mul_mont(fe_add($y, $y), $z);

    return [$x3, $y3, $z3];
}

sub _jac_add {
    my ($p, $q) = @_;
    return $q unless defined $p;
    return $p unless defined $q;

    my ($x1, $y1, $z1) = @$p;
    my ($x2, $y2, $z2) = @$q;

    my $z1z1 = fe_mul_mont($z1, $z1);
    my $z2z2 = fe_mul_mont($z2, $z2);
    my $u1   = fe_mul_mont($x1, $z2z2);
    my $u2   = fe_mul_mont($x2, $z1z1);
    my $s1   = fe_mul_mont($y1, fe_mul_mont($z2, $z2z2));
    my $s2   = fe_mul_mont($y2, fe_mul_mont($z1, $z1z1));

    my $h = fe_sub($u2, $u1);
    my $r = fe_sub($s2, $s1);

    return _jac_double($p) if fe_is_zero($h) && fe_is_zero($r);
    return undef if fe_is_zero($h);

    my $h2   = fe_mul_mont($h, $h);
    my $h3   = fe_mul_mont($h, $h2);
    my $u1h2 = fe_mul_mont($u1, $h2);

    my $x3 = fe_sub(fe_sub(fe_mul_mont($r, $r), $h3),
                    fe_add($u1h2, $u1h2));
    my $y3 = fe_sub(fe_mul_mont($r, fe_sub($u1h2, $x3)),
                    fe_mul_mont($s1, $h3));
    my $z3 = fe_mul_mont(fe_mul_mont($z1, $z2), $h);

    return [$x3, $y3, $z3];
}

sub _jac_to_affine {
    my ($p) = @_;
    return undef unless defined $p;
    my ($x, $y, $z) = @$p;
    return undef if fe_is_zero($z);

    # fe_inv は通常形式の値を扱うので、Z をいったん戻してから逆元を取り、
    # 結果をモンゴメリ形式に直して掛ける。
    my $zi  = to_mont(fe_inv(from_mont($z)));
    my $zi2 = fe_mul_mont($zi, $zi);
    my $zi3 = fe_mul_mont($zi2, $zi);
    return [ fe_mul_mont($x, $zi2), fe_mul_mont($y, $zi3) ];
}

# スカラー倍（モンゴメリ形式の点）。返り値はモンゴメリ形式のアフィン点。
sub _scalar_mul {
    my ($k_hex, $point) = @_;

    my $bits = _hex_to_bits($k_hex);
    my $acc;
    for my $bit (@$bits) {
        $acc = _jac_double($acc);
        if ($bit) {
            $acc = _jac_add($acc, [$point->[0], $point->[1], to_mont(fe_from_int('1'))]);
        }
    }
    return _jac_to_affine($acc);
}

sub _hex_to_bits {
    my ($hex) = @_;
    $hex = '0' x (64 - length $hex) . $hex if length $hex < 64;
    my @bits;
    for my $ch (split //, $hex) {
        my $v = hex $ch;
        for (my $b = 3; $b >= 0; $b--) {
            push @bits, ($v >> $b) & 1;
        }
    }
    shift @bits while @bits && !$bits[0];
    return \@bits;
}

# ---------------------------------------------------------------- 公開 API

# 秘密鍵（32 バイトの 16 進）から公開鍵（モンゴメリ形式でない 0x04||X||Y）
sub p256_pubkey {
    my ($priv_hex) = @_;
    my $g_mont = [ to_mont($GX), to_mont($GY) ];
    my $q = _scalar_mul($priv_hex, $g_mont);
    die "invalid private key\n" unless $q;
    return _mont_point_to_plain($q);
}

sub _mont_point_to_plain {
    my ($p) = @_;
    return [ from_mont($p->[0]), from_mont($p->[1]) ];
}

sub p256_serialize {
    my ($point) = @_;
    return "\x04" . fe_to_bytes($point->[0]) . fe_to_bytes($point->[1]);
}

sub p256_uncompress {
    my ($bytes) = @_;
    die "invalid public key encoding\n"
        unless defined $bytes && length($bytes) == 65 && ord(substr($bytes, 0, 1)) == 0x04;
    return [
        bytes_to_fe(substr($bytes, 1, 32)),
        bytes_to_fe(substr($bytes, 33, 32)),
    ];
}

sub bytes_to_fe {
    my ($b) = @_;
    return Disperl::Voice::Dave::Field256::bytes_to_limbs($b);
}

sub p256_ecdh {
    my ($priv_hex, $pub_point) = @_;
    my $p_mont = [ to_mont($pub_point->[0]), to_mont($pub_point->[1]) ];
    my $q = _scalar_mul($priv_hex, $p_mont);
    die "ECDH: point at infinity\n" unless $q;
    return fe_to_bytes(from_mont($q->[0]));
}

sub p256_on_curve {
    my ($point) = @_;
    my ($x, $y) = @$point;
    my $three = fe_from_int('3');
    my $left  = fe_sq($y);
    my $right = fe_add(fe_sub(fe_mul(fe_sq($x), $x), fe_mul($three, $x)), $B);
    return fe_cmp($left, $right) == 0 ? 1 : 0;
}

sub p256_valid_public {
    my ($point) = @_;
    return 0 unless $point && defined $point->[0];
    return p256_on_curve($point);
}

# ランダムな秘密鍵（64 桁 16 進）
sub p256_keygen {
    my $hex = unpack 'H*', random_bytes(32);
    # 0 と n 以上を避ける
    $hex = '1' . ('0' x 63) if $hex !~ /[1-9a-f]/;
    return $hex;
}

# バイト列 → スカラー。n 以上なら undef（RFC 9180 DeriveKeyPair の candidate 検査）
sub os2ip_mod_n {
    my ($bytes) = @_;
    my $v = sc_from_bytes($bytes);
    return undef if sc_cmp($v, sc_from_hex(sc_n_hex())) >= 0;
    return sc_to_hex($v);
}

# ---------------------------------------------------------------- 署名（mod n は別モジュール）

# ECDSA-P256-SHA256 署名。$msg_hash は 32 バイトのハッシュ。
# 返り値は (r, s) の 64 桁 16 進。
sub p256_sign {
    my ($priv_hex, $msg_hash) = @_;

    my $e = sc_from_hex(unpack 'H*', $msg_hash);
    my $d = sc_from_hex($priv_hex);

    while (1) {
        my $k = sc_random();
        next if sc_is_zero($k);

        my $g_mont = [ to_mont($GX), to_mont($GY) ];
        my $q = _scalar_mul(sc_to_hex($k), $g_mont);
        next unless $q;

        my $r = sc_reduce(sc_from_hex(unpack 'H*', fe_to_bytes(from_mont($q->[0]))));
        next if sc_is_zero($r);

        my $s = sc_mul(sc_inv($k), sc_add($e, sc_mul($d, $r)));
        next if sc_is_zero($s);

        return (sc_to_hex($r), sc_to_hex($s));
    }
}

sub p256_verify {
    my ($msg_hash, $r_hex, $s_hex, $pub_point) = @_;

    my $r = sc_from_hex($r_hex);
    my $s = sc_from_hex($s_hex);
    return 0 if sc_is_zero($r) || sc_is_zero($s);

    my $e = sc_from_hex(unpack 'H*', $msg_hash);
    my $w  = sc_inv($s);
    my $u1 = sc_mul($e, $w);
    my $u2 = sc_mul($r, $w);

    my $g_mont = [ to_mont($GX), to_mont($GY) ];
    my $q_mont = [ to_mont($pub_point->[0]), to_mont($pub_point->[1]) ];

    my $p1 = _scalar_mul(sc_to_hex($u1), $g_mont);
    my $p2 = _scalar_mul(sc_to_hex($u2), $q_mont);
    return 0 unless $p1 || $p2;

    my $sum = _jac_add(
        $p1 ? [ $p1->[0], $p1->[1], to_mont(fe_from_int('1')) ] : undef,
        $p2 ? [ $p2->[0], $p2->[1], to_mont(fe_from_int('1')) ] : undef,
    );
    my $aff = _jac_to_affine($sum);
    return 0 unless $aff;

    my $x = sc_reduce(sc_from_hex(unpack 'H*', fe_to_bytes(from_mont($aff->[0]))));
    return sc_cmp($x, $r) == 0 ? 1 : 0;
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::P256 - NIST P-256（ECDH / 点演算）

=head1 DESCRIPTION

体演算に Disperl::Voice::Dave::Field256（Pure Perl）を使う。
座標は内部でモンゴメリ形式で保持する。署名・検証は
Disperl::Voice::Dave::Scalar を読み込むと有効になる。

=cut
