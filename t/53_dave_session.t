use strict;
use warnings;
use Test::More;

use FindBin;
use lib "$FindBin::Bin/../lib";
use Disperl::Voice::Dave;
use Disperl::Voice::Dave::MLS qw(encode_mls_message decode_mls_message
                                 make_key_package_ref user_id_identity);
use Disperl::Voice::Dave::MLSState;

package FakeSession;
sub new { bless { exporter_secret => $_[1] }, $_[0] }
sub exporter_secret { $_[0]->{exporter_secret} }

package main;

# ---- ULEB128 ----
use Disperl::Voice::Dave::Util qw(uleb128_encode uleb128_decode);
{
    # (import is now file-wide)

    for my $v (0, 1, 127, 128, 255, 300, 16383, 16384, 0xffffffff) {
        my $b = uleb128_encode($v);
        my ($got, $len) = uleb128_decode($b, 0);
        is $got, $v, "uleb128 round trip $v";
        is $len, length($b), "uleb128 consumed all bytes for $v";
    }
    # 仕様の C 実装どおり、7 ビットずつ下位から切り出す
    is unpack('H*', uleb128_encode(0)),      '00',     'uleb128(0)';
    is unpack('H*', uleb128_encode(63)),     '3f',     'uleb128(63) is 1 byte';
    is unpack('H*', uleb128_encode(64)),     '40',     'uleb128(64)';
    is unpack('H*', uleb128_encode(127)),    '7f',     'uleb128(127)';
    is unpack('H*', uleb128_encode(128)),    '8001',   'uleb128(128)';
    is unpack('H*', uleb128_encode(300)),    'ac02',   'uleb128(300)';
    is unpack('H*', uleb128_encode(16383)),  'ff7f',   'uleb128(16383)';
    is unpack('H*', uleb128_encode(16384)),  '808001', 'uleb128(16384)';
    is unpack('H*', uleb128_encode(0xffffffff)), 'ffffffff0f', 'uleb128(2^32-1)';
}

# ---- フレーム形式 ----
{
    my $dave = Disperl::Voice::Dave->new(user_id => 42);
    $dave->{session} = FakeSession->new("\x11" x 32);

    my $opus = "\xaa" x 40;
    my $frame = $dave->encrypt_frame($opus);

    is substr($frame, -2), "\xfa\xfa", 'magic marker at end';
    my $supp = ord substr($frame, -3, 1);
    ok $supp >= 11, "supplemental size $supp includes 8-byte tag";
    ok length($frame) > length($opus), 'frame is bigger than plaintext';

    my $back = $dave->decrypt_frame($frame, 42);
    is $back, $opus, 'decrypt restores the opus frame';

    # 無音フレームは平文で通す
    is $dave->encrypt_frame("\xf8\xff\xfe"), "\xf8\xff\xfe", 'silence passes through';

    # タグを壊すと復号できない（平文のまま返る）
    my $bad = $frame;
    substr($bad, 0, 1) = chr(ord(substr($bad, 0, 1)) ^ 0xff);
    isnt $dave->decrypt_frame($bad, 42), $opus, 'tampered frame is not decrypted';
}

# ---- nonce の増加と世代 ----
{
    my $dave = Disperl::Voice::Dave->new(user_id => 7);
    $dave->{session} = FakeSession->new("\x22" x 32);

    my @frames = map { $dave->encrypt_frame("x" x 10) } 1 .. 3;
    my @nonces;
    for my $f (@frames) {
        my $supp = ord substr($f, -3, 1);
        my $pos = length($f) - $supp + 8;
        my ($n) = uleb128_decode($f, $pos);
        push @nonces, $n;
    }
    is_deeply \@nonces, [0, 1, 2], 'nonce increments per frame';

    # 世代は nonce の最上位バイト（2^24 フレームごとに 1 つ進む）
    $dave->{nonce} = 0x00ffffff;
    my $g0 = $dave->encrypt_frame("a" x 4);
    is $dave->decrypt_frame($g0, 7), "a" x 4, 'generation 0 frame decrypts';

    $dave->{nonce} = 0x01000000;
    my $g1 = $dave->encrypt_frame("b" x 4);
    my $supp = ord substr($g1, -3, 1);
    my ($n) = uleb128_decode($g1, length($g1) - $supp + 8);
    is $n, 0x01000000, 'nonce carries the generation byte';
    is $n >> 24, 1, 'generation is the most significant byte';
    is $dave->decrypt_frame($g1, 7), "b" x 4, 'frame from generation 1 decrypts';
}

# ---- ラチェットの決定性 ----
{
    require Disperl::Voice::Dave::KeySchedule;
    my $base = "\x33" x 16;
    my $k0 = Disperl::Voice::Dave::KeySchedule::sender_ratchet_key($base, 0);
    my $k1 = Disperl::Voice::Dave::KeySchedule::sender_ratchet_key($base, 1);
    is length($k0), 16, 'generation key is 16 bytes';
    isnt $k0, $k1, 'different generations give different keys';
    is $k0, Disperl::Voice::Dave::KeySchedule::sender_ratchet_key($base, 0),
        'ratchet is deterministic';
}

# ---- MLS の KeyPackage と署名 ----
{
    my $sess = Disperl::Voice::Dave::MLSState->new(
        user_id       => 123456789012345678,
        signing_key   => 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
        signature_pub => '',
        hpke_priv     => 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
        hpke_pub      => '',
    );

    require Disperl::Voice::Dave::P256;
    $sess->{signature_pub} = Disperl::Voice::Dave::P256::p256_serialize(
        Disperl::Voice::Dave::P256::p256_pubkey($sess->{signing_key}));
    $sess->{hpke_pub} = Disperl::Voice::Dave::P256::p256_serialize(
        Disperl::Voice::Dave::P256::p256_pubkey($sess->{hpke_priv}));

    my $kp_bytes = $sess->create_key_package;
    ok length($kp_bytes) > 100, 'key package encoded';

    require Disperl::Voice::Dave::MLS;
    my $kp = Disperl::Voice::Dave::MLS::decode_key_package($kp_bytes);
    is $kp->{version}, 1, 'key package version';
    is $kp->{cipher_suite}, 2, 'key package ciphersuite';
    ok Disperl::Voice::Dave::MLS::verify_key_package($kp), 'key package signature verifies';

    my $ref = make_key_package_ref($kp_bytes);
    is length($ref), 32, 'key package ref is 32 bytes';
}

# ---- グループ作成（1 人） ----
{
    my $sess = Disperl::Voice::Dave::MLSState->new(
        user_id       => 555,
        signing_key   => 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
        signature_pub => '',
        hpke_priv     => 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
        hpke_pub      => '',
    );
    require Disperl::Voice::Dave::P256;
    $sess->{signature_pub} = Disperl::Voice::Dave::P256::p256_serialize(
        Disperl::Voice::Dave::P256::p256_pubkey($sess->{signing_key}));
    $sess->{hpke_pub} = Disperl::Voice::Dave::P256::p256_serialize(
        Disperl::Voice::Dave::P256::p256_pubkey($sess->{hpke_priv}));

    ok $sess->create_group, 'create group';
    is $sess->epoch, 0, 'epoch 0';
    is $sess->leaf_count, 1, 'one leaf';
    is length($sess->tree_hash), 32, 'tree hash is 32 bytes';
    is length($sess->exporter_secret), 32, 'exporter secret is 32 bytes';

    my $base = $sess->export_media_base_secret;
    is length($base), 16, 'media base secret is 16 bytes';
    isnt $base, $sess->export_media_base_secret(556),
        'media base secret is per sender';
}

# ---- MLSMessage の往復 ----
{
    my $kp = "\x01\x02\x03";
    my $msg = encode_mls_message(5, $kp);
    my $d = decode_mls_message($msg);
    is $d->{version}, 1, 'msl version';
    is $d->{wire_format}, 5, 'wire format key_package';
    is $d->{body}, $kp, 'body round trips';
}

done_testing();
