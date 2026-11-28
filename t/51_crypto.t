use strict;
use warnings;
use Test::More;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Disperl::Voice::Crypto qw(chacha20_block chacha20_xor hchacha20 poly1305
    aead_chacha20poly1305_ietf_encrypt aead_chacha20poly1305_ietf_decrypt
    aead_xchacha20poly1305_ietf_encrypt aead_xchacha20poly1305_ietf_decrypt);

# RFC 8439 (ChaCha20 & Poly1305) と draft-irtf-cfrg-xchacha のテストベクタ
my $SUNSCREEN = "Ladies and Gentlemen of the class of '99: "
    . "If I could offer you only one tip for the future, sunscreen would be it.";

sub hexd { pack 'H*', $_[0] }

# ---- ChaCha20 (RFC 8439 2.3.2: serialized block) ----
{
    my $block = chacha20_block(
        hexd('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
        1,
        hexd('000000090000004a00000000'),
    );
    is unpack('H*', $block),
        '10f1e7e4d13b5915500fdd1fa32071c4'
      . 'c7d1f4c733c068030422aa9ac3d46c4e'
      . 'd2826446079faa0914c2d705d98b02a2'
      . 'b5129cd1de164eb9cbd083e8a2503c4e',
        'ChaCha20 block function (RFC 8439 2.3.2)';
}

# ---- ChaCha20 cipher (RFC 8439 2.4.2) ----
{
    my $ks = chacha20_xor(
        hexd('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
        1,
        hexd('000000000000004a00000000'),
        $SUNSCREEN,
    );
    is unpack('H*', $ks),
        '6e2e359a2568f98041ba0728dd0d6981'
      . 'e97e7aec1d4360c20a27afccfd9fae0b'
      . 'f91b65c5524733ab8f593dabcd62b357'
      . '1639d624e65152ab8f530c359f0861d8'
      . '07ca0dbf500d6a6156a38e088a22b65e'
      . '52bc514d16ccf806818ce91ab7793736'
      . '5af90bbf74a35be6b40b8eedf2785e42'
      . '874d',
        'ChaCha20 cipher (RFC 8439 2.4.2)';
}

# ---- Poly1305 (RFC 8439 2.5.2) ----
{
    my $tag = poly1305(
        hexd('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b'),
        'Cryptographic Forum Research Group',
    );
    is unpack('H*', $tag), 'a8061dc1305136c6c22b8baf0c0127a9',
        'Poly1305 (RFC 8439 2.5.2)';
}

# ---- AEAD_CHACHA20_POLY1305 (RFC 8439 2.8.2) ----
{
    my $key   = hexd('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    my $nonce = hexd('070000004041424344454647');
    my $aad   = hexd('50515253c0c1c2c3c4c5c6c7');

    my $ct = aead_chacha20poly1305_ietf_encrypt($SUNSCREEN, $aad, $nonce, $key);
    is unpack('H*', substr($ct, 0, -16)),
        'd31a8d34648e60db7b86afbc53ef7ec2'
      . 'a4aded51296e08fea9e2b5a736ee62d6'
      . '3dbea45e8ca9671282fafb69da92728b'
      . '1a71de0a9e060b2905d6a5b67ecd3b36'
      . '92ddbd7f2d778b8c9803aee328091b58'
      . 'fab324e4fad675945585808b4831d7bc'
      . '3ff4def08e4b7a9de576d26586cec64b'
      . '6116',
        'AEAD_CHACHA20_POLY1305 ciphertext (RFC 8439 2.8.2)';
    is unpack('H*', substr($ct, -16)), '1ae10b594f09e26a7e902ecbd0600691',
        'AEAD_CHACHA20_POLY1305 tag (RFC 8439 2.8.2)';

    my $pt = aead_chacha20poly1305_ietf_decrypt($ct, $aad, $nonce, $key);
    is $pt, $SUNSCREEN, 'AEAD_CHACHA20_POLY1305 decrypt';

    # タグ改ざんは検知する
    my $bad = $ct;
    substr($bad, -1, 1) = chr(ord(substr($bad, -1, 1)) ^ 0x01);
    eval { aead_chacha20poly1305_ietf_decrypt($bad, $aad, $nonce, $key) };
    like $@, qr/authentication failed/, 'tampered tag detected';
}

# ---- HChaCha20 (draft-irtf-cfrg-xchacha 2.2.1) ----
{
    my $subkey = hchacha20(
        hexd('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
        hexd('000000090000004a0000000031415927'),
    );
    is unpack('H*', $subkey),
        '82413b4227b27bfed30e42508a877d73'
      . 'a0f9e4d58a74a853c12ec41326d3ecdc',
        'HChaCha20 (draft-irtf-cfrg-xchacha 2.2.1)';
}

# ---- AEAD_XCHACHA20_POLY1305 (draft-irtf-cfrg-xchacha A.1) ----
{
    my $key   = hexd('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    my $nonce = hexd('404142434445464748494a4b4c4d4e4f5051525354555657');
    my $aad   = hexd('50515253c0c1c2c3c4c5c6c7');

    my $ct = aead_xchacha20poly1305_ietf_encrypt($SUNSCREEN, $aad, $nonce, $key);
    is unpack('H*', substr($ct, 0, -16)),
        'bd6d179d3e83d43b9576579493c0e939'
      . '572a1700252bfaccbed2902c21396cbb'
      . '731c7f1b0b4aa6440bf3a82f4eda7e39'
      . 'ae64c6708c54c216cb96b72e1213b452'
      . '2f8c9ba40db5d945b11b69b982c1bb9e'
      . '3f3fac2bc369488f76b2383565d3fff9'
      . '21f9664c97637da9768812f615c68b13'
      . 'b52e',
        'AEAD_XCHACHA20_POLY1305 ciphertext (draft A.1)';
    is unpack('H*', substr($ct, -16)), 'c0875924c1c7987947deafd8780acf49',
        'AEAD_XCHACHA20_POLY1305 tag (draft A.1)';

    my $pt = aead_xchacha20poly1305_ietf_decrypt($ct, $aad, $nonce, $key);
    is $pt, $SUNSCREEN, 'AEAD_XCHACHA20_POLY1305 decrypt';
}

# ---- ラウンドトリップ（空 / 1 バイト / ブロック境界） ----
{
    my $key   = "\x01" x 32;
    my $nonce = "\x02" x 24;

    for my $len (0, 1, 15, 16, 17, 63, 64, 65, 320) {
        my $pt = "\xa5" x $len;
        my $ct = aead_xchacha20poly1305_ietf_encrypt($pt, 'aad', $nonce, $key);
        my $rt = eval { aead_xchacha20poly1305_ietf_decrypt($ct, 'aad', $nonce, $key) };
        is $rt, $pt, "round trip len=$len";
    }
}

done_testing();
