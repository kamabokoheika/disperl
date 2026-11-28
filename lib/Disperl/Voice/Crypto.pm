package Disperl::Voice::Crypto;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';

our @EXPORT_OK = qw(
    chacha20_block chacha20_xor hchacha20 poly1305
    aead_chacha20poly1305_ietf_encrypt aead_chacha20poly1305_ietf_decrypt
    aead_xchacha20poly1305_ietf_encrypt aead_xchacha20poly1305_ietf_decrypt
);

# 依存モジュールなしの XChaCha20-Poly1305 実装。
# Discord 音声（voice gateway v8 / aead_xchacha20_poly1305_rtpsize）用。
#
# - ChaCha20 / HChaCha20: RFC 8439 / draft-irtf-cfrg-xchacha
# - Poly1305: RFC 8439。26bit リム x 5 本で 130bit 算術をやる
# - すべて pure Perl。CPU はそこそこ使うが 20ms フレームなら十分間に合う

my @SIGMA = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574);    # "expand 32-byte k"

sub rotl32 {
    my ($v, $n) = @_;
    $v &= 0xffffffff;
    return (($v << $n) | ($v >> (32 - $n))) & 0xffffffff;
}

sub _quarter_round {
    my ($x, $a, $b, $c, $d) = @_;

    $x->[$a] = ($x->[$a] + $x->[$b]) & 0xffffffff;
    $x->[$d] = rotl32($x->[$d] ^ $x->[$a], 16);
    $x->[$c] = ($x->[$c] + $x->[$d]) & 0xffffffff;
    $x->[$b] = rotl32($x->[$b] ^ $x->[$c], 12);
    $x->[$a] = ($x->[$a] + $x->[$b]) & 0xffffffff;
    $x->[$d] = rotl32($x->[$d] ^ $x->[$a], 8);
    $x->[$c] = ($x->[$c] + $x->[$d]) & 0xffffffff;
    $x->[$b] = rotl32($x->[$b] ^ $x->[$c], 7);
    return 1;
}

sub _rounds {
    my ($x) = @_;
    for (1 .. 10) {
        _quarter_round($x, 0, 4,  8, 12);
        _quarter_round($x, 1, 5,  9, 13);
        _quarter_round($x, 2, 6, 10, 14);
        _quarter_round($x, 3, 7, 11, 15);
        _quarter_round($x, 0, 5, 10, 15);
        _quarter_round($x, 1, 6, 11, 12);
        _quarter_round($x, 2, 7,  8, 13);
        _quarter_round($x, 3, 4,  9, 14);
    }
    return 1;
}

# 高速版: 変数直演算に展開した 20 ラウンド。chacha20_block / hchacha20 から使う。
sub _rounds16 {
    my ($x0, $x1, $x2, $x3, $x4, $x5, $x6, $x7,
        $x8, $x9, $x10, $x11, $x12, $x13, $x14, $x15) = @_;

    for (1 .. 10) {
        # 列ラウンド QR(0,4,8,12)
        $x0 = ($x0 + $x4) & 0xffffffff; my $t = $x12 ^ $x0; $x12 = (($t << 16) | ($t >> 16)) & 0xffffffff;
        $x8 = ($x8 + $x12) & 0xffffffff; $t = $x4 ^ $x8; $x4 = (($t << 12) | ($t >> 20)) & 0xffffffff;
        $x0 = ($x0 + $x4) & 0xffffffff; $t = $x12 ^ $x0; $x12 = (($t << 8) | ($t >> 24)) & 0xffffffff;
        $x8 = ($x8 + $x12) & 0xffffffff; $t = $x4 ^ $x8; $x4 = (($t << 7) | ($t >> 25)) & 0xffffffff;
        # QR(1,5,9,13)
        $x1 = ($x1 + $x5) & 0xffffffff; $t = $x13 ^ $x1; $x13 = (($t << 16) | ($t >> 16)) & 0xffffffff;
        $x9 = ($x9 + $x13) & 0xffffffff; $t = $x5 ^ $x9; $x5 = (($t << 12) | ($t >> 20)) & 0xffffffff;
        $x1 = ($x1 + $x5) & 0xffffffff; $t = $x13 ^ $x1; $x13 = (($t << 8) | ($t >> 24)) & 0xffffffff;
        $x9 = ($x9 + $x13) & 0xffffffff; $t = $x5 ^ $x9; $x5 = (($t << 7) | ($t >> 25)) & 0xffffffff;
        # QR(2,6,10,14)
        $x2 = ($x2 + $x6) & 0xffffffff; $t = $x14 ^ $x2; $x14 = (($t << 16) | ($t >> 16)) & 0xffffffff;
        $x10 = ($x10 + $x14) & 0xffffffff; $t = $x6 ^ $x10; $x6 = (($t << 12) | ($t >> 20)) & 0xffffffff;
        $x2 = ($x2 + $x6) & 0xffffffff; $t = $x14 ^ $x2; $x14 = (($t << 8) | ($t >> 24)) & 0xffffffff;
        $x10 = ($x10 + $x14) & 0xffffffff; $t = $x6 ^ $x10; $x6 = (($t << 7) | ($t >> 25)) & 0xffffffff;
        # QR(3,7,11,15)
        $x3 = ($x3 + $x7) & 0xffffffff; $t = $x15 ^ $x3; $x15 = (($t << 16) | ($t >> 16)) & 0xffffffff;
        $x11 = ($x11 + $x15) & 0xffffffff; $t = $x7 ^ $x11; $x7 = (($t << 12) | ($t >> 20)) & 0xffffffff;
        $x3 = ($x3 + $x7) & 0xffffffff; $t = $x15 ^ $x3; $x15 = (($t << 8) | ($t >> 24)) & 0xffffffff;
        $x11 = ($x11 + $x15) & 0xffffffff; $t = $x7 ^ $x11; $x7 = (($t << 7) | ($t >> 25)) & 0xffffffff;
        # 対角ラウンド QR(0,5,10,15)
        $x0 = ($x0 + $x5) & 0xffffffff; $t = $x15 ^ $x0; $x15 = (($t << 16) | ($t >> 16)) & 0xffffffff;
        $x10 = ($x10 + $x15) & 0xffffffff; $t = $x5 ^ $x10; $x5 = (($t << 12) | ($t >> 20)) & 0xffffffff;
        $x0 = ($x0 + $x5) & 0xffffffff; $t = $x15 ^ $x0; $x15 = (($t << 8) | ($t >> 24)) & 0xffffffff;
        $x10 = ($x10 + $x15) & 0xffffffff; $t = $x5 ^ $x10; $x5 = (($t << 7) | ($t >> 25)) & 0xffffffff;
        # QR(1,6,11,12)
        $x1 = ($x1 + $x6) & 0xffffffff; $t = $x12 ^ $x1; $x12 = (($t << 16) | ($t >> 16)) & 0xffffffff;
        $x11 = ($x11 + $x12) & 0xffffffff; $t = $x6 ^ $x11; $x6 = (($t << 12) | ($t >> 20)) & 0xffffffff;
        $x1 = ($x1 + $x6) & 0xffffffff; $t = $x12 ^ $x1; $x12 = (($t << 8) | ($t >> 24)) & 0xffffffff;
        $x11 = ($x11 + $x12) & 0xffffffff; $t = $x6 ^ $x11; $x6 = (($t << 7) | ($t >> 25)) & 0xffffffff;
        # QR(2,7,8,13)
        $x2 = ($x2 + $x7) & 0xffffffff; $t = $x13 ^ $x2; $x13 = (($t << 16) | ($t >> 16)) & 0xffffffff;
        $x8 = ($x8 + $x13) & 0xffffffff; $t = $x7 ^ $x8; $x7 = (($t << 12) | ($t >> 20)) & 0xffffffff;
        $x2 = ($x2 + $x7) & 0xffffffff; $t = $x13 ^ $x2; $x13 = (($t << 8) | ($t >> 24)) & 0xffffffff;
        $x8 = ($x8 + $x13) & 0xffffffff; $t = $x7 ^ $x8; $x7 = (($t << 7) | ($t >> 25)) & 0xffffffff;
        # QR(3,4,9,14)
        $x3 = ($x3 + $x4) & 0xffffffff; $t = $x14 ^ $x3; $x14 = (($t << 16) | ($t >> 16)) & 0xffffffff;
        $x9 = ($x9 + $x14) & 0xffffffff; $t = $x4 ^ $x9; $x4 = (($t << 12) | ($t >> 20)) & 0xffffffff;
        $x3 = ($x3 + $x4) & 0xffffffff; $t = $x14 ^ $x3; $x14 = (($t << 8) | ($t >> 24)) & 0xffffffff;
        $x9 = ($x9 + $x14) & 0xffffffff; $t = $x4 ^ $x9; $x4 = (($t << 7) | ($t >> 25)) & 0xffffffff;
    }

    return ($x0, $x1, $x2, $x3, $x4, $x5, $x6, $x7,
            $x8, $x9, $x10, $x11, $x12, $x13, $x14, $x15);
}

# ChaCha20 ブロック関数（RFC 8439 §2.3）。64 バイトを返す。
sub chacha20_block {
    my ($key, $counter, $nonce) = @_;

    die "key must be 32 bytes\n" unless defined $key && length $key == 32;
    die "nonce must be 12 bytes\n" unless defined $nonce && length $nonce == 12;

    my @st = (
        @SIGMA,
        unpack('V8', $key),
        $counter & 0xffffffff,
        unpack('V3', $nonce),
    );
    my @x = _rounds16(@st);

    return pack 'V16', map { ($x[$_] + $st[$_]) & 0xffffffff } 0 .. 15;
}

# ChaCha20 暗号（RFC 8439 §2.4。32bit カウンタ + 12 バイト nonce）。
sub chacha20_xor {
    my ($key, $counter, $nonce, $data) = @_;

    my $out = '';
    my $len = length $data;
    my $c   = $counter & 0xffffffff;

    # 64 バイト境界のチャンクは長さ制限なしで XOR できる
    my $full = $len - ($len % 64);
    for (my $off = 0; $off < $full; $off += 64) {
        $out .= substr($data, $off, 64) ^ chacha20_block($key, $c++, $nonce);
    }
    if ($full < $len) {
        my $chunk = substr($data, $full);
        my $ks    = chacha20_block($key, $c, $nonce);
        $out .= substr($chunk ^ $ks, 0, length $chunk);
    }
    return $out;
}

# HChaCha20（draft-irtf-cfrg-xchacha §2.2）。XChaCha20 のサブキー導出用。
sub hchacha20 {
    my ($key, $nonce16) = @_;

    die "key must be 32 bytes\n" unless defined $key && length $key == 32;
    die "nonce must be 16 bytes\n" unless defined $nonce16 && length $nonce16 == 16;

    my @st = (@SIGMA, unpack('V8', $key), unpack('V4', $nonce16));
    my @x = _rounds16(@st);

    # 初期 state は加算しない。先頭 4 ワードと末尾 4 ワードを LE 直列化して返す
    return pack 'V8', @x[0 .. 3, 12 .. 15];
}

# Poly1305（RFC 8439 §2.5）。16 バイトのタグを返す。
# h / r を 26bit リム x 5 本（連続パッキング）で持つ。
#   limb[i] = 130bit 値の bit 26i..26i+25
sub poly1305 {
    my ($key, $msg) = @_;

    die "key must be 32 bytes (r 16 + pad 16)\n" unless defined $key && length $key == 32;

    # r = clamp(key[0..16]): 各ワードの上位 2bit を落とす（RFC 8439 §2.5）
    my @t = unpack('V4', $key);
    $t[0] &= 0x0fffffff;
    $t[1] &= 0x0ffffffc;
    $t[2] &= 0x0ffffffc;
    $t[3] &= 0x0ffffffc;
    my ($r0, $r1, $r2, $r3, $r4) = _load26(pack('V4', @t) . "\x00\x00\x00\x00", 0);
    my ($s1, $s2, $s3, $s4) = map { $_ * 5 } ($r1, $r2, $r3, $r4);

    my @pad = unpack('V4', substr($key, 16, 16));

    my ($h0, $h1, $h2, $h3, $h4) = (0, 0, 0, 0, 0);
    my $pos = 0;
    my $len = length $msg;

    while ($len - $pos >= 16) {
        ($h0, $h1, $h2, $h3, $h4) =
            _acc($h0, $h1, $h2, $h3, $h4, substr($msg, $pos, 16), 1);
        ($h0, $h1, $h2, $h3, $h4) =
            _mul($h0, $h1, $h2, $h3, $h4, $r0, $r1, $r2, $r3, $r4, $s1, $s2, $s3, $s4);
        $pos += 16;
    }

    # 端数ブロック: msg || 0x01 || 0x00... （hibit なし）
    if ($pos < $len) {
        my $tail = substr($msg, $pos) . "\x01";
        $tail .= "\x00" x (16 - length $tail) if length $tail < 16;
        ($h0, $h1, $h2, $h3, $h4) = _acc($h0, $h1, $h2, $h3, $h4, $tail, 0);
        ($h0, $h1, $h2, $h3, $h4) =
            _mul($h0, $h1, $h2, $h3, $h4, $r0, $r1, $r2, $r3, $r4, $s1, $s2, $s3, $s4);
    }

    # フルキャリー
    my $c = $h1 >> 26; $h1 &= 0x3ffffff;
    $h2 += $c; $c = $h2 >> 26; $h2 &= 0x3ffffff;
    $h3 += $c; $c = $h3 >> 26; $h3 &= 0x3ffffff;
    $h4 += $c; $c = $h4 >> 26; $h4 &= 0x3ffffff;
    $h0 += $c * 5; $c = $h0 >> 26; $h0 &= 0x3ffffff;
    $h1 += $c;

    # h + 5 を計算し、2^130 を超えたら h >= p なのでそちらを採用
    my $g0 = $h0 + 5; $c = $g0 >> 26; $g0 &= 0x3ffffff;
    my $g1 = $h1 + $c; $c = $g1 >> 26; $g1 &= 0x3ffffff;
    my $g2 = $h2 + $c; $c = $g2 >> 26; $g2 &= 0x3ffffff;
    my $g3 = $h3 + $c; $c = $g3 >> 26; $g3 &= 0x3ffffff;
    my $g4 = $h4 + $c; $c = $g4 >> 26; $g4 &= 0x3ffffff;

    if ($c) {
        ($h0, $h1, $h2, $h3, $h4) = ($g0, $g1, $g2, $g3, $g4);
    }

    # mod 2^128 で 32bit ワード 4 本へ
    my $w0 = (($h0)       | ($h1 << 26)) & 0xffffffff;
    my $w1 = (($h1 >>  6) | ($h2 << 20)) & 0xffffffff;
    my $w2 = (($h2 >> 12) | ($h3 << 14)) & 0xffffffff;
    my $w3 = (($h3 >> 18) | ($h4 <<  8)) & 0xffffffff;

    # mac = (h + pad) mod 2^128
    my $sum = $w0 + $pad[0]; $w0 = $sum & 0xffffffff; $c = $sum >> 32;
    $sum = $w1 + $pad[1] + $c; $w1 = $sum & 0xffffffff; $c = $sum >> 32;
    $sum = $w2 + $pad[2] + $c; $w2 = $sum & 0xffffffff; $c = $sum >> 32;
    $sum = $w3 + $pad[3] + $c; $w3 = $sum & 0xffffffff;

    return pack 'V4', $w0, $w1, $w2, $w3;
}

# バイト列（16 バイト + hibit）を 130bit 値として h に加算する。
# hibit は 2^128 の位置（最終ブロックでは 0）。
sub _acc {
    my ($h0, $h1, $h2, $h3, $h4, $block, $hibit) = @_;

    my @t = unpack('V4', $block);
    $h0 +=  $t[0]                       & 0x3ffffff;
    $h1 += (($t[0] >> 26) | ($t[1] <<  6)) & 0x3ffffff;
    $h2 += (($t[1] >> 20) | ($t[2] << 12)) & 0x3ffffff;
    $h3 += (($t[2] >> 14) | ($t[3] << 18)) & 0x3ffffff;
    $h4 += (($t[3] >>  8) | ($hibit << 24));

    return ($h0, $h1, $h2, $h3, $h4);
}

# テスト用: 連続 26bit パッキングでリムを取り出す（hibit あり）。
sub _load26 {
    my ($bytes, $hibit) = @_;
    my @t = unpack('V4', substr($bytes, 0, 16));
    return (
        $t[0] & 0x3ffffff,
        (($t[0] >> 26) | ($t[1] <<  6)) & 0x3ffffff,
        (($t[1] >> 20) | ($t[2] << 12)) & 0x3ffffff,
        (($t[2] >> 14) | ($t[3] << 18)) & 0x3ffffff,
        (($t[3] >>  8) | (($hibit ? 1 : 0) << 24)),
    );
}

# h *= r mod (2^130 - 5)。リムは 26bit だが直前の繰り上がりで
# h1 が 2^26+1 まで伸びることがある。積は 2^52 x 5 < 2^55 で 64bit に収まる。
sub _mul {
    my ($h0, $h1, $h2, $h3, $h4, $r0, $r1, $r2, $r3, $r4, $s1, $s2, $s3, $s4) = @_;

    my $d0 = $h0 * $r0 + $h1 * $s4 + $h2 * $s3 + $h3 * $s2 + $h4 * $s1;
    my $d1 = $h0 * $r1 + $h1 * $r0 + $h2 * $s4 + $h3 * $s3 + $h4 * $s2;
    my $d2 = $h0 * $r2 + $h1 * $r1 + $h2 * $r0 + $h3 * $s4 + $h4 * $s3;
    my $d3 = $h0 * $r3 + $h1 * $r2 + $h2 * $r1 + $h3 * $r0 + $h4 * $s4;
    my $d4 = $h0 * $r4 + $h1 * $r3 + $h2 * $r2 + $h3 * $r1 + $h4 * $r0;

    my $c = $d0 >> 26; $h0 = $d0 & 0x3ffffff;
    $d1 += $c; $c = $d1 >> 26; $h1 = $d1 & 0x3ffffff;
    $d2 += $c; $c = $d2 >> 26; $h2 = $d2 & 0x3ffffff;
    $d3 += $c; $c = $d3 >> 26; $h3 = $d3 & 0x3ffffff;
    $d4 += $c; $c = $d4 >> 26; $h4 = $d4 & 0x3ffffff;
    $h0 += $c * 5; $c = $h0 >> 26; $h0 &= 0x3ffffff;
    $h1 += $c;

    return ($h0, $h1, $h2, $h3, $h4);
}

sub _pad16 {
    my ($data) = @_;
    my $mod = length($data) % 16;
    return $mod ? ("\x00" x (16 - $mod)) : '';
}

# ChaCha20-Poly1305（IETF, 12 バイト nonce）。
sub aead_chacha20poly1305_ietf_encrypt {
    my ($plaintext, $aad, $nonce12, $key) = @_;
    return _aead_ietf($plaintext, $aad, $nonce12, $key, 1);
}

sub aead_chacha20poly1305_ietf_decrypt {
    my ($data, $aad, $nonce12, $key) = @_;
    return _aead_ietf_decrypt($data, $aad, $nonce12, $key);
}

# XChaCha20-Poly1305（draft-irtf-cfrg-xchacha §2.3）。
#   subkey = HChaCha20(key, nonce[0..15])
#   AEAD   = ChaCha20-Poly1305-IETF(subkey, nonce = 0x00000000 || nonce[16..23])
sub aead_xchacha20poly1305_ietf_encrypt {
    my ($plaintext, $aad, $nonce24, $key) = @_;

    die "nonce must be 24 bytes\n" unless defined $nonce24 && length $nonce24 == 24;

    my $subkey  = hchacha20($key, substr($nonce24, 0, 16));
    my $nonce12 = "\x00\x00\x00\x00" . substr($nonce24, 16, 8);
    return _aead_ietf($plaintext, $aad, $nonce12, $subkey, 1);
}

sub aead_xchacha20poly1305_ietf_decrypt {
    my ($data, $aad, $nonce24, $key) = @_;

    die "nonce must be 24 bytes\n" unless defined $nonce24 && length $nonce24 == 24;

    my $subkey  = hchacha20($key, substr($nonce24, 0, 16));
    my $nonce12 = "\x00\x00\x00\x00" . substr($nonce24, 16, 8);
    return _aead_ietf_decrypt($data, $aad, $nonce12, $subkey);
}

sub _aead_ietf {
    my ($plaintext, $aad, $nonce12, $key, $with_tag) = @_;

    $aad = '' unless defined $aad;

    # Poly1305 のワンタイムキー（カウンタ 0 の最初の 32 バイト）
    my $otk = substr(chacha20_block($key, 0, $nonce12), 0, 32);
    # 暗号化はカウンタ 1 から
    my $ct = chacha20_xor($key, 1, $nonce12, $plaintext);

    my $mac_data = $aad . _pad16($aad)
                 . $ct . _pad16($ct)
                 . pack('Q< Q<', length($aad), length $ct);

    my $tag = poly1305($otk, $mac_data);
    return $with_tag ? $ct . $tag : $ct;
}

sub _aead_ietf_decrypt {
    my ($data, $aad, $nonce12, $key) = @_;

    $aad = '' unless defined $aad;
    die "ciphertext too short\n" unless defined $data && length($data) >= 16;

    my $ct  = substr($data, 0, length($data) - 16);
    my $tag = substr($data, -16);

    my $otk = substr(chacha20_block($key, 0, $nonce12), 0, 32);

    my $mac_data = $aad . _pad16($aad)
                 . $ct . _pad16($ct)
                 . pack('Q< Q<', length($aad), length $ct);

    die "Poly1305 authentication failed\n"
        unless poly1305($otk, $mac_data) eq $tag;

    return chacha20_xor($key, 1, $nonce12, $ct);
}

1;

__END__

=head1 NAME

Disperl::Voice::Crypto - 依存モジュールなしの ChaCha20 / XChaCha20-Poly1305

=head1 SYNOPSIS

    use Disperl::Voice::Crypto;

    my $ct = aead_xchacha20poly1305_ietf_encrypt($pt, $aad, $nonce24, $key);
    my $pt = aead_xchacha20poly1305_ietf_decrypt($ct, $aad, $nonce24, $key);

=head1 DESCRIPTION

Discord の音声接続（transport encryption）で必須の
C<aead_xchacha20_poly1305_rtpsize> を pure Perl で提供する。
RFC 8439 と draft-irtf-cfrg-xchacha のテストベクタで検証済み（t/crypto.t）。

=cut
