use strict;
use warnings;
use Test::More;

use FindBin;
use lib "$FindBin::Bin/../lib";

use JSON::PP;
use Disperl::Voice;
use Disperl::Voice::Crypto qw(aead_xchacha20poly1305_ietf_decrypt);
use Disperl::Voice::Dave;

my $JSON = JSON::PP->new->utf8(1);

# ---- fake MLS state（exporter_secret だけ持つ） ----
package FakeDaveSession;
sub new { bless { exporter_secret => $_[1] }, $_[0] }
sub exporter_secret { $_[0]->{exporter_secret} }

# ---- fake voice WebSocket ----
package FakeWS;
our @SCRIPT;          # 次の recv_frame で返すメッセージ（ハッシュ）
our @INSTANCES;       # 作成されたインスタンス（url と送信内容の記録）

sub connect {
    my ($class, %args) = @_;
    my $self = bless { url => $args{url}, sent => [], binary => [], idx => 0, closed => 0 }, $class;
    push @INSTANCES, $self;
    return $self;
}

sub send_text   { push @{ $_[0]->{sent} }, $_[1] }
sub send_frame  { push @{ $_[0]->{binary} }, [ $_[1], $_[2] ] }
sub closed      { $_[0]->{closed} ? 1 : 0 }
sub close       { $_[0]->{closed} = 1 }

sub recv_frame {
    my ($self, %args) = @_;
    my $item = $SCRIPT[$self->{idx}++];
    return undef unless $item;
    # 生バイナリは {binary => ...} で渡す
    return { opcode => 0x2, payload => $item->{binary} } if ref $item eq 'HASH' && exists $item->{binary};
    return { opcode => 0x1, payload => JSON::PP::encode_json($item) };
}

sub script { @SCRIPT = @_ }
sub last_sent {
    my ($self) = @_;
    my @sent = map { $JSON->decode($_) } @{ $self->{sent} };
    return wantarray ? @sent : $sent[-1];
}
sub find_sent {
    my ($self, $op) = @_;
    my @sent = map { $JSON->decode($_) } @{ $self->{sent} };
    return grep { ($_->{op} // -1) == $op } @sent;
}

# ---- fake UDP（IP Discovery に応答する） ----
package FakeUDP;
our @INSTANCES;
sub new {
    my $self = bless { sent => [], response => '' }, $_[0];
    push @INSTANCES, $self;
    return $self;
}
sub send {
    my ($self, $data) = @_;
    my ($type) = unpack('n', $data);
    # IP Discovery は音声パケットではないので別に記録する
    push @{ $self->{sent} }, $data if $type != 0x1;
    if ($type == 0x1) {
        my $ssrc = unpack('x4 N', $data);
        $self->{response} = pack('nn', 0x2, 70)
            . pack('N', $ssrc)
            . pack('Z64', '127.0.0.1')
            . pack('n', 54321);
    }
    return 1;
}
sub can_read { 1 }
sub recv     { $_[1] = $_[0]->{response}; return 1 }
sub blocking { 1 }
sub close    { 1 }

# ---- テスト本体 ----
package main;

my $SECRET = pack('C*', 0x01 .. 0x20);    # 32 バイト

sub make_script {
    my (%args) = @_;
    FakeWS->script(
        { op => 8, d => { heartbeat_interval => 41250, v => 8 } },
        { op => 2, d => {
            ssrc  => 1,
            ip    => '127.0.0.1',
            port  => 50000,
            modes => ['aead_xchacha20_poly1305_rtpsize', 'xsalsa20_poly1305'],
        }},
        { op => 4, d => {
            mode => 'aead_xchacha20_poly1305_rtpsize',
            secret_key => [unpack('C*', $SECRET)],
            (exists $args{dave_version} ? (dave_protocol_version => $args{dave_version}) : ()),
        }},
    );
}

sub make_voice {
    my (%args) = @_;
    make_script(dave_version => delete $args{dave_version});
    return Disperl::Voice->new(
        token      => 'voice-token',
        endpoint   => 'voice.discord.media:443',
        server_id  => '100',
        user_id    => '200',
        session_id => 'sess-1',
        udp_factory => sub { FakeUDP->new },
        ws_class    => 'FakeWS',
        %args,
    );
}

subtest 'handshake' => sub {
    my $v = make_voice;
    ok $v->connect, 'connect succeeds';
    is $v->state, 'ready', 'state is ready';
    is $v->ssrc, 1, 'ssrc from Ready';

    my $ws = $FakeWS::INSTANCES[-1];
    is $ws->{url}, 'wss://voice.discord.media:443/?v=8', 'ws url uses v=8';

    my ($identify) = $ws->find_sent(0);
    is_deeply $identify->{d}, {
        server_id  => '100',
        user_id    => '200',
        session_id => 'sess-1',
        token      => 'voice-token',
        max_dave_protocol_version => 0,
    }, 'identify payload';

    my ($select) = $ws->find_sent(1);
    is $select->{d}{protocol}, 'udp', 'select protocol is udp';
    is $select->{d}{data}{mode}, 'aead_xchacha20_poly1305_rtpsize', 'mode is xchacha rtpsize';
    is $select->{d}{data}{address}, '127.0.0.1', 'discovered ip';
    is $select->{d}{data}{port}, 54321, 'discovered port';

    my ($speaking) = $ws->find_sent(5);
    is $speaking->{d}{speaking}, 0, 'initial speaking is silent';
    is $speaking->{d}{ssrc}, 1, 'speaking ssrc';

    my ($wants) = $ws->find_sent(15);
    is $wants->{d}{any}, 0, 'media sink wants any=0 (受信音声を要求しない)';
};

subtest 'rtp packets' => sub {
    my $v = make_voice;
    ok $v->connect, 'connect';

    my $udp = $FakeUDP::INSTANCES[-1];
    my $ws = $FakeWS::INSTANCES[-1];

    my $src = FakeSource->new(map { ("\x00" x 20) } 1 .. 3);
    ok $v->play($src), 'play source';

    # 20ms 間隔なので時刻を進めながら pump する
    my $t = $v->{next_frame_at};
    $v->pump($t + 0.02 * $_) for 0 .. 2;
    is scalar(@{ $udp->{sent} }), 3, '3 frames sent';
    is scalar($ws->find_sent(5)), 2, 'speaking on sent once';

    my $packet = $udp->{sent}[0];
    is length($packet) > 36, 1, 'packet has header + payload + nonce';

    my $header = substr($packet, 0, 12);
    is unpack('H2', substr($packet, 0, 1)), '80', 'RTP version+flags 0x80';
    is unpack('H2', substr($packet, 1, 1)), '78', 'RTP payload type 0x78';
    is unpack('n', substr($packet, 2, 2)), 0, 'sequence starts at 0';
    is unpack('N', substr($packet, 4, 4)), 0, 'timestamp starts at 0';
    is unpack('N', substr($packet, 8, 4)), 1, 'ssrc';

    # 復号して音声フレームを検証（AAD = RTP header、nonce は先頭 4 バイト + 0 埋め）
    my $nonce24 = substr($packet, -4) . ("\x00" x 20);
    my $pt = aead_xchacha20poly1305_ietf_decrypt(
        substr($packet, 12, length($packet) - 16),
        $header,
        $nonce24,
        $SECRET,
    );
    is $pt, "\x00" x 20, 'decrypted audio frame matches source';

    # 2 つ目のパケット: nonce カウンタが増えている
    my $packet2 = $udp->{sent}[1];
    is unpack('N', substr($packet2, -4)), 1, 'nonce counter increments';
    is unpack('n', substr($packet2, 2, 2)), 1, 'sequence increments';
    is unpack('N', substr($packet2, 4, 4)), 960, 'timestamp +960 (20ms @ 48kHz)';
};

subtest 'silence and track end' => sub {
    my $v = make_voice;
    ok $v->connect, 'connect';

    my $udp = $FakeUDP::INSTANCES[-1];
    my $ws = $FakeWS::INSTANCES[-1];

    my @ended;
    $v->{on_track_end} = sub { push @ended, $_[0] };

    my $src = FakeSource->new(("\x11" x 10));
    $src->{done} = 1;    # すぐ終端
    $v->play($src);

    # 終端 → 無音 5 フレーム → on_track_end（20ms ずつ時刻を進める）
    my $t = $v->{next_frame_at};
    $v->pump($t + 0.02 * $_) for 0 .. 9;

    is scalar(@ended), 1, 'track_end fired once';
    is $ended[0], 'finished', 'reason is finished';

    my @packets = @{ $udp->{sent} };
    is scalar(@packets), 5, '5 silence frames (source was already done)';
    my $last = $packets[-1];
    my $plain = aead_xchacha20poly1305_ietf_decrypt(
        substr($last, 12, length($last) - 16),
        substr($last, 0, 12),
        substr($last, -4) . ("\x00" x 20),
        $SECRET,
    );
    is $plain, "\xf8\xff\xfe", 'last packet is the opus silence frame';

    my ($off) = grep { ($_->{d}{speaking} // -1) == 0 } $ws->find_sent(5);
    ok $off, 'speaking turned off after silence';
};

subtest 'pause and resume' => sub {
    my $v = make_voice;
    ok $v->connect, 'connect';

    my $udp = $FakeUDP::INSTANCES[-1];

    my $src = FakeSource->new(map { ("\x33" x 10) } 1 .. 100);
    $v->play($src);
    my $t = $v->{next_frame_at};
    $v->pump($t);
    my $before = scalar(@{ $udp->{sent} });
    ok $v->pause, 'pause';
    $v->pump($t + 0.02 * ($_ + 1)) for 0 .. 5;
    is scalar(@{ $udp->{sent} }) - $before, 5, '5 silence frames after pause';
    my $after_pause = scalar(@{ $udp->{sent} });
    $v->pump($t + 0.02 * $_ + 1) for 1 .. 5;
    is scalar(@{ $udp->{sent} }), $after_pause, 'no packets while paused';

    ok $v->resume, 'resume';
    $v->pump($t + 3);
    ok scalar(@{ $udp->{sent} }) > $after_pause, 'packets resume';
};

subtest 'dave media wrapping' => sub {
    my $dave = Disperl::Voice::Dave->new(user_id => 200);
    $dave->{session} = FakeDaveSession->new("\x44" x 32);    # exporter だけ使う

    my $v = make_voice(dave => $dave, dave_version => 1);
    ok $v->connect, 'connect';
    is $v->{dave_enabled}, 1, 'dave enabled from select_protocol_ack';
    is $v->{dave_version}, 1, 'dave protocol version 1';

    my $udp = $FakeUDP::INSTANCES[-1];
    my $ws  = $FakeWS::INSTANCES[-1];

    my ($identify) = $ws->find_sent(0);
    is $identify->{d}{max_dave_protocol_version}, 1, 'identify advertises DAVE 1';

    my $src = FakeSource->new(map { ("\x5a" x 32) } 1 .. 2);
    $v->play($src);
    my $t = $v->{next_frame_at};
    $v->pump($t + 0.02 * $_) for 0 .. 1;

    my $packet = $udp->{sent}[0];
    my $plain = aead_xchacha20poly1305_ietf_decrypt(
        substr($packet, 12, length($packet) - 16),
        substr($packet, 0, 12),
        substr($packet, -4) . ("\x00" x 20),
        $SECRET,
    );
    isnt $plain, "\x5a" x 32, 'payload is DAVE encrypted inside transport';
    is substr($plain, -2), "\xfa\xfa", 'DAVE magic marker is present';

    my $opus = $dave->decrypt_frame($plain, 200);
    is $opus, "\x5a" x 32, 'DAVE layer decrypts back to opus';
};

subtest 'dave json opcode' => sub {
    my $dave = Disperl::Voice::Dave->new(user_id => 200);
    my $v = make_voice(dave => $dave);

    $v->_handle({ op => 24, d => { epoch => 1, protocol_version => 1 } });
    is $dave->{session} ? 1 : 0, 1, 'epoch 1 creates an MLS session';
    ok $dave->{state} eq 'pending', 'state is pending after prepare_epoch';

    my @out = $dave->drain_outbound;
    is scalar(@out), 1, 'key package queued';
    is ord(substr($out[0], 2, 1)), 26, 'opcode 26 (key_package)';
};

subtest 'heartbeat format' => sub {
    my $v = make_voice;
    ok $v->connect, 'connect';

    my $ws = $FakeWS::INSTANCES[-1];
    my @sent_before = scalar $ws->find_sent(3);

    $v->{next_heartbeat} = 0;    # 強制的に heartbeat 時刻にする
    $v->pump;

    my ($hb) = $ws->find_sent(3);
    ok $hb, 'heartbeat sent';
    ok $hb->{d}{t} > 0, 'heartbeat has t (ms)';
    ok !defined($hb->{d}{seq_ack}), 'seq_ack starts as null';
};

# ---- テスト用音源 ----
package FakeSource;
sub new {
    my ($class, @frames) = @_;
    return bless { frames => \@frames, idx => 0, done => 0 }, $class;
}
sub next_frame { $_[0]->{idx} < @{ $_[0]->{frames} } ? $_[0]->{frames}[ $_[0]->{idx}++ ] : undef }
sub done { $_[0]->{done} }

package main;

done_testing();
