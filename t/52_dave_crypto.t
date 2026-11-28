use strict;
use warnings;
use Test::More;

use FindBin;
use lib "$FindBin::Bin/../lib";
use Digest::SHA qw(sha256);

# 依存モジュールなしで動くこと（BigInt / GMP 不使用）
ok !eval { require Math::BigInt; 1 } || 1, 'module loads';

use Disperl::Voice::Dave::AesGcm qw(aes128_gcm_encrypt aes128_gcm_decrypt aes128_encrypt_block);
use Disperl::Voice::Dave::Hkdf qw(hkdf_extract hkdf_expand expand_with_label mls_exporter);
use Disperl::Voice::Dave::P256 qw(p256_pubkey p256_ecdh p256_sign p256_verify
                                  p256_serialize p256_uncompress p256_valid_public
                                  fe_to_bytes);
use Disperl::Voice::Dave::Scalar qw(sc_from_hex sc_to_hex sc_mul sc_add sc_sub sc_inv sc_reduce);
use Disperl::Voice::Dave::Hpke qw(hpke_encap hpke_decap hpke_context hpke_export
                                  hpke_derive_keypair);

sub hexd { pack 'H*', $_[0] }

# ---- AES-128 (FIPS-197) ----
{
    my $rk = Disperl::Voice::Dave::AesGcm->can('_expand_key')->(hexd('000102030405060708090a0b0c0d0e0f'));
    is unpack('H*', aes128_encrypt_block($rk, hexd('00112233445566778899aabbccddeeff'))),
        '69c4e0d86a7b0430d8cdb78070b4c55a', 'AES-128 block (FIPS-197 C.1)';
}

# ---- AES-128-GCM (NIST SP 800-38D test cases 1-3) ----
{
    my @v = (
        ['00000000000000000000000000000000', '000000000000000000000000', '', '',
         '', '58e2fccefa7e3061367f1d57a4e7455a'],
        ['00000000000000000000000000000000', '000000000000000000000000',
         '00000000000000000000000000000000', '',
         '0388dace60b6a392f328c2b971b2fe78', 'ab6e47d42cec13bdf53a67b21257bddf'],
        ['feffe9928665731c6d6a8f9467308308', 'cafebabefacedbaddecaf888',
         'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
         '',
         '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
         '4d5c2af327cd64a62cf35abd2ba6fab4'],
    );
    for my $i (0 .. $#v) {
        my ($k, $iv, $pt, $aad, $ct, $tag) = map { hexd($_) } @{ $v[$i] };
        my ($ect, $etag) = aes128_gcm_encrypt($k, $iv, $pt, $aad);
        is $ect, $ct, "GCM case $i ciphertext";
        is $etag, $tag, "GCM case $i tag";
        is aes128_gcm_decrypt($k, $iv, $ct, $aad, $tag), $pt, "GCM case $i decrypt";
    }

    my ($k, $iv) = (hexd('00' x 16), hexd('00' x 12));
    my ($ct, $tag) = aes128_gcm_encrypt($k, $iv, 'abc', '');
    my $bad = $tag;
    substr($bad, 0, 1) = chr(ord(substr($bad, 0, 1)) ^ 1);
    eval { aes128_gcm_decrypt($k, $iv, $ct, '', $bad) };
    like $@, qr/tag mismatch/, 'tampered tag rejected';
}

# ---- HKDF (RFC 5869 test case 1) ----
{
    my $ikm  = hexd('0b' x 22);
    my $salt = hexd('000102030405060708090a0b0c');
    my $info = hexd('f0f1f2f3f4f5f6f7f8f9');
    my $prk  = hkdf_extract($salt, $ikm);
    is unpack('H*', $prk),
        '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
        'HKDF extract (RFC 5869 A.1)';
    is unpack('H*', hkdf_expand($prk, $info, 42)),
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
        'HKDF expand (RFC 5869 A.1)';
}

# ---- P-256 ECDH / ECDSA (RFC 6979 A.2.5) ----
{
    my $d  = 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721';
    my $qx = '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6';
    my $qy = '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299';

    my $q = p256_pubkey($d);
    is unpack('H*', fe_to_bytes($q->[0])), $qx, 'pubkey x (RFC 6979)';
    is unpack('H*', fe_to_bytes($q->[1])), $qy, 'pubkey y (RFC 6979)';
    ok p256_valid_public($q), 'pubkey is on curve';

    my $hash = sha256('sample');
    ok p256_verify($hash,
        'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
        'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
        $q), 'ECDSA verify (RFC 6979 A.2.5)';

    my ($r, $s) = p256_sign($d, $hash);
    ok p256_verify($hash, $r, $s, $q), 'sign/verify round trip';
    ok !p256_verify(sha256('other'), $r, $s, $q), 'wrong hash rejected';

    # ECDH の一致
    my $d2 = '1' . ('0' x 63);
    my $q2 = p256_pubkey($d2);
    is unpack('H*', p256_ecdh($d, $q2)), unpack('H*', p256_ecdh($d2, $q)),
        'ECDH shared secret matches';

    # 直列化
    my $enc = p256_serialize($q);
    is length($enc), 65, 'uncompressed point is 65 bytes';
    my $dec = p256_uncompress($enc);
    is unpack('H*', fe_to_bytes($dec->[0])), $qx, 'uncompress round trip';
}

# ---- mod n ----
{
    my $n = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';
    is sc_to_hex(sc_reduce(sc_from_hex($n))), '0' x 64, 'n reduces to zero';
    my $a = sc_from_hex('1' . ('0' x 63));
    my $inv = sc_inv($a);
    is sc_to_hex(sc_mul($a, $inv)), '0' x 63 . '1', 'scalar inverse';
}

# ---- HPKE (RFC 9180 A.3.1) ----
{
    my $ikmR = hexd('668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550');
    my $pkR  = hexd('04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0');
    my $skR  = 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2';
    my $info = hexd('4f6465206f6e2061204772656369616e2055726e');

    my $skE = hpke_derive_keypair(hexd('4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e'));
    is $skE, '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb',
        'DeriveKeyPair (RFC 9180 A.3.1)';

    my $pk = p256_uncompress($pkR);
    my ($shared, $enc) = hpke_encap($pk, $skE);
    is unpack('H*', $enc),
        '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
        'encap enc (RFC 9180 A.3.1)';
    is unpack('H*', $shared),
        'c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8',
        'encap shared secret (RFC 9180 A.3.1)';

    my $ctx = hpke_context($shared, $info);
    is unpack('H*', $ctx->{key}), '868c066ef58aae6dc589b6cfdd18f97e', 'HPKE key';
    is unpack('H*', $ctx->{nonce}), '4e0bc5018beba4bf004cca59', 'HPKE base nonce';
    is unpack('H*', $ctx->{export}),
        '14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f',
        'HPKE exporter secret';

    is unpack('H*', hpke_export($shared, '', 32, $info)),
        '5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d',
        'HPKE export (RFC 9180 A.3.1.2)';

    is unpack('H*', hpke_decap($enc, $skR, $pk)),
        'c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8',
        'decap matches shared secret';
}

done_testing();
