package Disperl::Voice;
use strict;
use warnings;

our $VERSION = '0.1.0';

use JSON::PP;
use IO::Socket::INET;
use IO::Select;
use Time::HiRes qw(time);
use Disperl::WebSocket;
use Disperl::Voice::Crypto qw(aead_xchacha20poly1305_ietf_encrypt);

my $JSON = JSON::PP->new->utf8(1);

# Discord Voice Gateway (v8) + RTP 音声送信。
#
# ドキュメント:
#   https://docs.discord.com/developers/topics/voice-connections.md
#
# 使い方（親プロセス側で VOICE_STATE_UPDATE / VOICE_SERVER_UPDATE を集めて渡す）:
#   my $voice = Disperl::Voice->new(
#       token      => ...,      # VOICE_SERVER_UPDATE の token
#       endpoint   => ...,      # VOICE_SERVER_UPDATE の endpoint
#       server_id  => ...,      # guild id
#       user_id    => ...,      # bot のユーザー ID
#       session_id => ...,      # VOICE_STATE_UPDATE の session_id
#   );
#   $voice->connect;                      # handshake（ブロッキング）
#   $voice->play($source);                # next_frame() を持つ音源
#   while (1) {
#       my $t = $voice->idle_timeout;
#       ... select で待つ ...
#       $voice->pump;                     # 受信 / heartbeat / フレーム送信
#   }
#
# 暗号化は aead_xchacha20_poly1305_rtpsize（voice gateway で常に提供される必須モード）。

my $FRAME_INTERVAL = 0.020;              # opus 20ms フレーム
my $SILENCE_FRAME  = "\xf8\xff\xfe";     # opus の無音フレーム
my $REQUIRED_MODE  = 'aead_xchacha20_poly1305_rtpsize';
my $PAYLOAD_TYPE   = 0x78;               # RTP payload type（opus）
my $TIMESTAMP_INC  = 960;                # 48kHz / 20ms

sub new {
    my ($class, %args) = @_;

    for my $k (qw(token endpoint server_id user_id session_id)) {
        die "$k is required\n" unless defined $args{$k} && length $args{$k};
    }

    return bless {
        %args,
        ws_class  => $args{ws_class} // 'Disperl::WebSocket',
        udp_factory => $args{udp_factory},
        timeout   => $args{timeout} // 10,

        state            => 'idle',
        ws               => undef,
        udp              => undef,
        ssrc             => undef,
        secret_key       => undef,
        v                => 8,
        heartbeat_interval => 41.25,
        next_heartbeat   => 0,
        awaiting_ack     => 0,
        seq_seen         => -1,          # v8 の buffered resume 用（受信メッセージの seq）
        resuming         => 0,
        last_seq_ack     => -1,          # heartbeat の seq_ack（初期は -1 / null）

        source           => undef,
        paused           => 0,
        silence_left     => 0,
        end_reason       => undef,       # 無音フレーム送り切った後に on_track_end へ渡す
        speaking         => 0,
        seq              => 0,
        timestamp        => 0,
        nonce            => 0,
        next_frame_at    => 0,
        played_frames    => 0,

        dave             => $args{dave},      # Disperl::Voice::Dave（省略時は無効）
        dave_version     => 0,
        dave_enabled     => 0,
    }, $class;
}

sub state     { $_[0]->{state} }
sub ssrc      { $_[0]->{ssrc} }
sub elapsed   { $_[0]->{played_frames} * $FRAME_INTERVAL }
sub playing   { $_[0]->{source} ? 1 : 0 }
sub paused    { $_[0]->{paused} ? 1 : 0 }

# select 用 fileno（音声 WS と UDP）。未接続なら undef。
sub fh {
    my ($self) = @_;
    return undef unless $self->{ws} && !$self->{ws}->closed;
    my $fh = $self->{ws}{sock} or return undef;
    return fileno($fh);
}

sub udp_fh {
    my ($self) = @_;
    return undef unless $self->{udp};
    return fileno($self->{udp});
}

# ---------------------------------------------------------------- handshake

# 音声 WS + UDP の handshake を済ませる（ブロッキング）。Session Description で完了。
sub connect {
    my ($self) = @_;

    my $endpoint = $self->{endpoint};
    $endpoint =~ s{^[a-z]+://}{};
    $endpoint .= ':443' if $endpoint !~ /:\d+\z/;

    my $ws = $self->{ws_class}->connect(
        url     => "wss://$endpoint/?v=8",
        timeout => $self->{timeout},
    );
    $self->{ws} = $ws;

    my $hello = $self->_expect(8);
    $self->{v} = $hello->{d}{v} // 8;
    my $raw_interval = ($hello->{d}{heartbeat_interval} // 41250) / 1000;
    # discord.py 準拠：ハートビート間隔は最大 5 秒に制限する
    $self->{heartbeat_interval} = $raw_interval < 5.0 ? $raw_interval : 5.0;

    $self->_send({ op => 0, d => {
        server_id  => "$self->{server_id}",
        user_id    => "$self->{user_id}",
        session_id => $self->{session_id},
        token      => $self->{token},
        # DAVE（E2EE）。dave を渡されたときだけ交渉する
        max_dave_protocol_version => ($self->{dave} ? 1 : 0),
    }});

    my $ready = $self->_expect(2);
    $self->{ssrc}  = $ready->{d}{ssrc};
    my @modes = @{ $ready->{d}{modes} // [] };
    die "voice server does not offer $REQUIRED_MODE\n"
        unless grep { $_ eq $REQUIRED_MODE } @modes;

    $self->_udp_connect($ready->{d}{ip}, $ready->{d}{port});
    my ($ip, $port) = $self->_ip_discovery;
    $ip   = $ready->{d}{ip}   unless defined $ip;
    $port = $ready->{d}{port} unless defined $port;
    $self->{ready_ip}   = $ip;
    $self->{ready_port} = $port;

    # Select Protocol を送信（セッションにつき 1 回）
    $self->_send_select_protocol;

    my $desc = $self->_expect(4);
    $self->{secret_key} = pack('C*', @{ $desc->{d}{secret_key} // [] });
    die "Session Description has no 32-byte secret_key\n"
        unless length($self->{secret_key}) == 32;

    if (my $dave = $self->{dave}) {
        $self->{dave_version} = $desc->{d}{dave_protocol_version} // 0;
        if ($self->{dave_version} > 0) {
            $dave->{protocol_version} = $self->{dave_version};
            $self->{dave_enabled} = 1;
        }
    }

    $self->{seq}           = 0;
    $self->{timestamp}     = 0;
    $self->{nonce}         = 0;
    $self->{played_frames} = 0;
    $self->{source}        = undef;
    $self->{paused}        = 0;
    $self->{silence_left}  = 0;
    $self->{end_reason}    = undef;
    $self->{speaking}      = 0;
    $self->{next_frame_at} = 0;
    $self->{awaiting_ack}  = 0;
    $self->{last_seq_ack}  = -1;

    # audio を送る前に最低 1 回 Speaking を送る（初期値は無音）
    $self->_send({ op => 5, d => { speaking => 0, delay => 0, ssrc => $self->{ssrc} } });
    # 受信音声は使わないので要求しない（op 15 は voice gateway v5 以降）
    if (($self->{v} // 0) >= 5) {
        $self->_send({ op => 15, d => { any => 0 } });
    }

    # Hello受信後に即座にハートビートを送信（discord.py 準拠）
    $self->_send({ op => 3, d => {
        t       => int(time() * 1000),
        seq_ack => $self->{last_seq_ack},
    }});
    my $now = time;
    $self->{awaiting_ack}    = 1;
    $self->{last_heartbeat_at} = $now;
    $self->{next_heartbeat}  = $now + $self->{heartbeat_interval};

    $self->{state} = 'ready';
    my $cb = $self->{on_state};
    if ($cb) { my $ok = eval { $cb->('ready'); 1 }; $self->_report($@) unless $ok; }
    return 1;
}

# ---------------------------------------------------------------- sources

# 音源をセットして再生を始める。$source は next_frame() と done を持つオブジェクト。
sub play {
    my ($self, $source) = @_;
    die "voice is not ready\n" unless $self->{state} eq 'ready';
    die "source must provide next_frame\n"
        unless ref $source && $source->can('next_frame');

    $self->{source}        = $source;
    $self->{paused}        = 0;
    $self->{silence_left}  = 0;
    $self->{end_reason}    = undef;
    $self->{next_frame_at} = time;
    return 1;
}

# 再生をやめる（5 フレームの無音を送ってから on_track_end('stopped') を出す）。
sub stop_source {
    my ($self) = @_;
    return 0 unless $self->{source} || $self->{silence_left};
    $self->{source}     = undef;
    $self->{paused}     = 0;
    $self->{silence_left} = 5 unless $self->{silence_left} > 5;
    $self->{end_reason} = 'stopped';
    return 1;
}

sub pause {
    my ($self) = @_;
    return 0 unless $self->{source} && !$self->{paused};
    $self->{paused}       = 1;
    $self->{silence_left} = 5;
    return 1;
}

sub resume {
    my ($self) = @_;
    return 0 unless $self->{paused};
    $self->{paused}       = 0;
    $self->{silence_left} = 0;
    $self->{end_reason}   = undef;
    $self->{next_frame_at} = time;
    return 1;
}

# 接続を閉じる（VC から出る際は親側で gateway の op 4 も送ること）。
sub disconnect {
    my ($self) = @_;
    $self->{state}  = 'idle';
    $self->{source} = undef;
    if (my $ws = $self->{ws}) {
        eval { $ws->close(1000) };
    }
    $self->{ws} = undef;
    if (my $udp = $self->{udp}) {
        eval { $udp->close };
    }
    $self->{udp} = undef;
    return 1;
}

# ---------------------------------------------------------------- pump

# 次のイベント（フレーム送信 or heartbeat）までの秒数。接続が無ければ undef。
sub idle_timeout {
    my ($self, $now) = @_;
    $now = time unless defined $now;

    return undef unless $self->{ws} && !$self->{ws}->closed;

    my $t = $self->{next_heartbeat} - $now;
    if ($self->{state} eq 'ready') {
        my $f = $self->{next_frame_at} - $now;
        $t = $f if defined $f && $f < $t;
    }
    $t = 0 if $t < 0;
    $t = 0.05 if $t > 0.05;   # 受信漏れを避けるため上限は短めに
    return $t;
}

# 1 ステップ進める。受信（ノンブロッキング）/ heartbeat / フレーム送信。
sub pump {
    my ($self, $now) = @_;
    $now = time unless defined $now;

    return unless $self->{ws} && !$self->{ws}->closed;

    # 受信（1 回の pump で最大 20 メッセージ）
    my $count = 0;
    while ($count++ < 20) {
        my $frame = eval { $self->{ws}->recv_frame(timeout => 0) };
        if (my $err = $@) {
            # timeout 以外のエラーは切れた扱いにする
            $self->_reconnect("voice ws error: $err");
            return;
        }
        last unless $frame;
        if ($frame->{opcode} == 8) {
            warn "[voice] WS close frame: code=" . ($frame->{code} // '?') . "\n";
            # 4006 = セッション無効 → Resume は試さず、セッションを破棄して切断扱いにする
            if (defined $frame->{code} && $frame->{code} == 4006) {
                $self->{session_id} = undef;
                $self->{seq_seen}   = undef;
            }
            $self->_reconnect('voice ws closed (code ' . ($frame->{code} // '?') . ')');
            return;
        }
        if ($frame->{opcode} == 2) {
            $self->_handle_binary($frame->{payload});
            next;
        }
        my $msg = eval { $JSON->decode($frame->{payload}) };
        warn "[voice] WS recv: op=" . ($msg->{op}//'?') . " seq=" . ($msg->{seq}//'-') . "\n" if ref $msg eq 'HASH';
        $self->_handle($msg) if ref $msg eq 'HASH';
    }

    my $flush_err = eval { $self->_flush_dave; 1 };
    unless ($flush_err) {
        my $err = $@ || 'flush dave failed';
        $err =~ s/\s+\z//;
        $self->_reconnect("voice ws error: $err");
        return;
    }

    # ゾンビ検知: discord.py 準拠。heartbeat_timeout=60秒で ACK 未受信なら切断
    if ($self->{awaiting_ack} && $now - $self->{last_heartbeat_at} > 60) {
        $self->_reconnect('heartbeat ACK not received');
        return;
    }

    if ($now >= $self->{next_heartbeat}) {
        my $seq_ack = defined($self->{last_seq_ack}) ? $self->{last_seq_ack} : -1;
        $self->_send({ op => 3, d => {
            t       => int($now * 1000),
            seq_ack => $seq_ack,
        }});
        $self->{awaiting_ack}    = 1;
        $self->{last_heartbeat_at} = $now;
        $self->{next_heartbeat}  = $now + $self->{heartbeat_interval};
    }

    my $send_err = eval { $self->_send_frames($now) if $self->{state} eq 'ready'; 1 };
    unless ($send_err) {
        my $err = $@ || 'send frames failed';
        $err =~ s/\s+\z//;
        $self->_reconnect("voice ws error: $err");
        return;
    }
    return 1;
}

sub _handle {
    my ($self, $msg) = @_;

    my $op = $msg->{op} // -1;
    $self->{seq_seen} = $msg->{seq} if defined $msg->{seq};
    $self->{last_seq_ack} = $msg->{seq} if defined $msg->{seq};

    if ($op >= 21 && $op <= 24) {   # DAVE の JSON メッセージ
        $self->{dave}->handle_json($msg) if $self->{dave};
        $self->_flush_dave;
        return 1;
    }

    if ($op == 6) {                 # Heartbeat ACK
        $self->{awaiting_ack} = 0;
    } elsif ($op == 9) {            # Resumed
        $self->{resuming} = 0;
        $self->{state}    = 'ready';
        $self->{awaiting_ack} = 0;
        $self->{next_heartbeat} = time + $self->{heartbeat_interval} * 0.5;
        # Resume 後は Select Protocol を送信しない（セッションは維持される）
    } elsif ($op == 5 || $op == 13) {
        # 他ユーザーの Speaking / ClientDisconnect。受信音声は使わない。
    }
    return 1;
}

# DAVE のバイナリメッセージ（op 20-31）
sub _handle_binary {
    my ($self, $payload) = @_;

    my $dave = $self->{dave} or return 1;
    my $ok = eval { $dave->handle_binary($payload); 1 };
    unless ($ok) {
        my $err = $@ || 'dave binary failed';
        $err =~ s/\s+\z//;
        $self->_report("DAVE: $err");
    }
    $self->_flush_dave;
    return 1;
}

# DAVE が送りたがっているメッセージを WS に流す
sub _flush_dave {
    my ($self) = @_;
    my $dave = $self->{dave} or return 1;
    my $ws = $self->{ws} or return 1;
    return 1 if $ws->closed;

    for my $json ($dave->drain_outbound_json) {
        eval { $ws->send_text($json) };
    }
    for my $bin ($dave->drain_outbound) {
        eval { $ws->send_frame(0x2, $bin) };
    }
    return 1;
}

# Select Protocol を送信（セッションにつき 1 回、connect / Resume 後に必須）
sub _send_select_protocol {
    my ($self) = @_;

    my $ip   = $self->{ready_ip}   // '';
    my $port = $self->{ready_port} // 0;
    return unless $ip && $port;

    $self->_send({ op => 1, d => {
        protocol => 'udp',
        data     => { address => $ip, port => $port, mode => $REQUIRED_MODE },
    }});
    return 1;
}

# ---------------------------------------------------------------- frames

sub _send_frames {
    my ($self, $now) = @_;

    my $budget = 10;    # 遅延からの追い上げ上限
    while ($now >= $self->{next_frame_at} && $budget-- > 0) {
        my $opus;

        # 一時停止中は無音だけを送り、残りが尽きたら止まる
        if ($self->{paused}) {
            last unless $self->{silence_left} > 0;
            $self->_send_opus($SILENCE_FRAME);
            $self->{silence_left}--;
            $self->_set_speaking(0) if $self->{silence_left} == 0;
            $self->{next_frame_at} += $FRAME_INTERVAL;
            next;
        }

        if (my $src = $self->{source}) {
            if ($src->can('done') && $src->done) {
                $self->{source}      = undef;
                $self->{silence_left} = 5;
                $self->{end_reason}  = 'finished';
            } else {
                my $ok = eval { $opus = $src->next_frame; 1 };
                unless ($ok) {
                    my $err = $@ || 'source error';
                    $err =~ s/\s+\z//;
                    $self->_report($err);
                    $self->{source}      = undef;
                    $self->{silence_left} = 5;
                    $self->{end_reason}  = 'error';
                }
            }
        }

        if (defined $opus) {
            $self->_set_speaking(1);
            $self->_send_opus($opus);
            $self->{played_frames}++;
        } elsif ($self->{silence_left} > 0) {
            $self->_send_opus($SILENCE_FRAME);
            $self->{silence_left}--;
            if ($self->{silence_left} == 0) {
                $self->_set_speaking(0);
                if (defined(my $reason = $self->{end_reason})) {
                    $self->{end_reason} = undef;
                    my $cb = $self->{on_track_end};
                    if ($cb) {
                        my $ok = eval { $cb->($reason); 1 };
                        $self->_report($@) unless $ok;
                    }
                }
            }
        } else {
            last;    # 送るべきものが無い
        }

        $self->{next_frame_at} += $FRAME_INTERVAL;
    }
    return 1;
}

# RTP パケット構築（docs: Voice Packet Structure）。
#   header: 0x80 0x78 seq(2BE) timestamp(4BE) ssrc(4BE)
#   nonce : 24 バイト。先頭 4 バイト = 32bit インクリメント値（big endian）、残り 0
#   packet: header || (音声 + Poly1305 tag) || nonce の先頭 4 バイト
#   AAD   = RTP header
sub _send_opus {
    my ($self, $opus) = @_;

    my $header = pack('CCnNN', 0x80, $PAYLOAD_TYPE,
        $self->{seq}, $self->{timestamp}, $self->{ssrc});

    my $nonce = "\x00" x 24;
    substr($nonce, 0, 4) = pack('N', $self->{nonce} & 0xffffffff);

    # DAVE 有効時は E2EE で包んでから transport 暗号をかける
    my $payload = $opus;
    if ($self->{dave_enabled} && $self->{dave}) {
        $payload = $self->{dave}->encrypt_frame($opus);
    }

    my $encrypted = aead_xchacha20poly1305_ietf_encrypt(
        $payload, $header, $nonce, $self->{secret_key});

    $self->{udp}->send($header . $encrypted . substr($nonce, 0, 4));

    $self->{seq}       = ($self->{seq} + 1) & 0xffff;
    $self->{timestamp} = ($self->{timestamp} + $TIMESTAMP_INC) & 0xffffffff;
    $self->{nonce}     = ($self->{nonce} + 1) & 0xffffffff;
    return 1;
}

sub _set_speaking {
    my ($self, $on) = @_;
    $on = $on ? 1 : 0;
    return if $self->{speaking} == $on;
    $self->{speaking} = $on;
    $self->_send({ op => 5, d => { speaking => $on, delay => 0, ssrc => $self->{ssrc} } });
    return 1;
}

# ---------------------------------------------------------------- internals

sub _send {
    my ($self, $payload) = @_;

    return 0 unless $self->{ws} && !$self->{ws}->closed;

    my $ok = eval { $self->{ws}->send_text($JSON->encode($payload)); 1 };
    unless ($ok) {
        my $err = $@ || 'send failed';
        $err =~ s/\s+\z//;
        $self->_report("WebSocket write error: $err");
        $self->_reconnect("voice ws write error: $err");
        return 0;
    }
    return 1;
}

# 指定 op のメッセージを待つ（connect 中のブロッキング待ち）。
sub _expect {
    my ($self, $want) = @_;

    while (1) {
        my $frame = $self->{ws}->recv_frame(timeout => $self->{timeout});
        die "voice ws closed while waiting for op $want (code "
            . ($frame->{code} // '?') . ")\n"
            if $frame && $frame->{opcode} == 8;
        die "Timed out waiting for voice op $want\n" unless $frame;

        if ($frame->{opcode} == 2) {
            $self->_handle_binary($frame->{payload});
            next;
        }

        my $msg = eval { $JSON->decode($frame->{payload}) };
        next unless ref $msg eq 'HASH';

        my $op = $msg->{op} // -1;
        $self->{seq_seen} = $msg->{seq} if defined $msg->{seq};

        # DAVE の JSON メッセージ（21/22/24）を処理
        if ($op >= 21 && $op <= 24 && $self->{dave}) {
            $self->{dave}->handle_json($msg);
            $self->_flush_dave;
            next;
        }

        return $msg if $op == $want;
        # 待っている間に来た他のメッセージは無視（Speaking など）
    }
}

sub _udp_connect {
    my ($self, $ip, $port) = @_;

    if (my $factory = $self->{udp_factory}) {
        $self->{udp} = $factory->($ip, $port);
        return 1;
    }

    $self->{udp} = IO::Socket::INET->new(
        PeerAddr => $ip,
        PeerPort => $port,
        Proto    => 'udp',
        Timeout  => $self->{timeout},
    ) or die "voice UDP connect failed ($ip:$port): $!\n";
    $self->{udp}->blocking(0);
    return 1;
}

# IP Discovery（NAT 越け）。外部 IP とポートを得る。
sub _ip_discovery {
    my ($self) = @_;

    my $req = pack('nn N a64 n', 0x1, 70, $self->{ssrc}, '', 0);

    for (1 .. 5) {
        $self->{udp}->send($req);
        next unless $self->_udp_can_read(1.0);
        my $buf = '';
        $self->{udp}->recv($buf, 256);
        next unless length($buf) >= 74;
        my ($ip, $port) = $self->_parse_discovery($buf);
        return ($ip, $port) if defined $ip;
    }
    return (undef, undef);
}

sub _udp_can_read {
    my ($self, $timeout) = @_;
    my $udp = $self->{udp};
    # テスト用 fake は can_read を持つ
    return $udp->can_read($timeout) if ref $udp && $udp->can('can_read');
    return IO::Select->new($udp)->can_read($timeout);
}

sub _parse_discovery {
    my ($self, $buf) = @_;

    my ($type) = unpack('n', $buf);
    return (undef, undef) unless $type == 0x2;

    my ($ip)   = unpack('x8 Z64', $buf);
    my ($port) = unpack('x72 n', $buf);
    return ($ip, $port);
}

# 接続が切れたら Resume を試み、無理なら disconnected を報告する。
sub _reconnect {
    my ($self, $reason) = @_;

    my $ws = $self->{ws};
    $self->{ws} = undef;
    eval { $ws->close(1000) } if $ws;

    # セッションが無効（4006 などで破棄済み）なら Resume は試さない
    unless (defined $self->{session_id}) {
        $self->{state} = 'disconnected';
        my $cb = $self->{on_state};
        if ($cb) { my $ok = eval { $cb->('disconnected', $reason); 1 }; $self->_report($@) unless $ok; }
        return 0;
    }

    if ($self->_resume) {
        $self->_report("voice: reconnected ($reason)");
        return 1;
    }

    $self->{state} = 'disconnected';
    my $cb = $self->{on_state};
    if ($cb) { my $ok = eval { $cb->('disconnected', $reason); 1 }; $self->_report($@) unless $ok; }
    return 0;
}

# 新しい WS で op 7 Resume。成功なら op 9 Resumed で ready に戻る。
# Resume は選択済みプロトコルを保持するので Select Protocol の再送はしない。
sub _resume {
    my ($self) = @_;

    return 0 unless $self->{secret_key};

    my $endpoint = $self->{endpoint};
    $endpoint =~ s{^[a-z]+://}{};
    $endpoint .= ':443' if $endpoint !~ /:\d+\z/;

    my $ok = eval {
        my $ws = $self->{ws_class}->connect(
            url     => "wss://$endpoint/?v=8",
            timeout => $self->{timeout},
        );
        $self->{ws} = $ws;
        $self->_expect(8);
        $self->_send({ op => 7, d => {
            server_id  => "$self->{server_id}",
            session_id => $self->{session_id},
            token      => $self->{token},
            seq_ack    => $self->{seq_seen},
        }});
        $self->_expect(9);
        $self->{resuming} = 1;
        my $now = time;
        $self->{awaiting_ack}    = 0;
        $self->{last_heartbeat_at} = $now;
        $self->{next_heartbeat}  = $now + $self->{heartbeat_interval};
        1;
    };
    unless ($ok) {
        my $err = $@ || 'resume failed';
        $err =~ s/\s+\z//;
        # 4006 = セッション無効 → session_id を破棄して MusicBot 側で新しいセッションを開始させる
        if ($err =~ /4006/) {
            $self->{session_id} = undef;
            $self->{seq_seen}   = undef;
        }
        $self->_report("voice resume failed: $err");
        $self->{ws} = undef;
    }
    return $ok ? 1 : 0;
}

sub _report {
    my ($self, $message) = @_;

    if ($self->{on_error}) {
        my $ok = eval { $self->{on_error}->($message); 1 };
        warn "voice on_error failed: $@" unless $ok;
        return;
    }
    warn(($message =~ /\n\z/) ? $message : "$message\n");
}

1;

__END__

=head1 NAME

Disperl::Voice - Discord 音声接続（voice gateway v8 + RTP 送信）

=head1 SYNOPSIS

    use Disperl::Voice;

    my $voice = Disperl::Voice->new(
        token      => $voice_token,     # VOICE_SERVER_UPDATE
        endpoint   => $endpoint,
        server_id  => $guild_id,
        user_id    => $bot_user_id,
        session_id => $session_id,      # VOICE_STATE_UPDATE
        on_state     => sub { ... },
        on_track_end => sub { ... },
        on_error     => sub { ... },
    );

    $voice->connect;                 # handshake（ブロッキング）
    $voice->play($track);            # next_frame() / done を持つ音源オブジェクト
    $voice->pause; $voice->resume; $voice->stop_source;

    # イベントループ側
    my $timeout = $voice->idle_timeout // 1;
    ... select で待ったあと ...
    $voice->pump;

=head1 DESCRIPTION

disperl（Disperl::WebSocket を流用）に音声チャンネル対応を足すモジュール。

- 音声 WS: identify / ready / select protocol / session description / heartbeat(v8, seq_ack) / resume
- UDP: IP Discovery、RTP パケット送信
- 暗号化: C<aead_xchacha20_poly1305_rtpsize>（Disperl::Voice::Crypto、依存なし）
- 音声: opus 20ms フレーム、無音フレーム補間、Speaking 更新
- DAVE (E2EE) には未対応（max_dave_protocol_version 0 で参加）

=head1 NOTES

- VC への参加 / 退出はメイン gateway の op 4（Voice State Update）で行う。
  REST の voice-states PATCH は stage チャンネル専用なので使えない。
- Select Protocol はセッションにつき 1 回だけ送る。

=cut
