use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use JSON::PP;
use Disperl::Gateway;

my $json = JSON::PP->new->utf8(1);

sub frame {
    my ($msg) = @_;
    return { opcode => 1, payload => $json->encode($msg) };
}

# WebSocket の代わりに、あらかじめ積んだフレームを返す偽クライアント
package FakeWS;

our $INSTANCE;
our $LAST_URL;
our $LAST_ARGS;
our @CONNECTIONS;

sub new {
    my ($class, %args) = @_;
    return bless {
        sent   => [],
        queue  => $args{queue} || [],
        closed => 0,
    }, $class;
}

sub connect {
    my ($class, %args) = @_;
    $LAST_URL  = $args{url};
    $LAST_ARGS = \%args;
    return shift @CONNECTIONS if @CONNECTIONS;
    return $INSTANCE;
}

sub send_text {
    my ($self, $text) = @_;
    push @{ $self->{sent} }, $text;
    return 1;
}

sub recv_frame {
    my ($self, %args) = @_;
    return shift @{ $self->{queue} };
}

sub close {
    my ($self, $code) = @_;
    $self->{closed} = $code // 1;
    return 1;
}

sub sent { $_[0]->{sent} }

package main;

subtest 'token is required' => sub {
    eval { Disperl::Gateway->new() };
    like $@, qr/Bot token is required/, 'dies without token';
};

subtest 'intents' => sub {
    my $messages_bits = Disperl::Gateway->intent_bits(qw(GUILDS GUILD_MESSAGES));
    is $messages_bits, 513, 'GUILDS | GUILD_MESSAGES';

    my $content_bits = Disperl::Gateway->intent_bits(qw(GUILDS MESSAGE_CONTENT));
    is $content_bits, 1 | 32768, 'MESSAGE_CONTENT bit';

    eval { Disperl::Gateway->intent_bits('NOPE') };
    like $@, qr/Unknown intent: NOPE/, 'unknown intent dies';

    my $default = Disperl::Gateway->new(token => 't');
    is $default->intents, 513, 'default intents';

    my $custom = Disperl::Gateway->new(token => 't', intents => [qw(GUILDS MESSAGE_CONTENT)]);
    is $custom->intents, 1 | 32768, 'array form';
};

subtest 'dispatch: READY and MESSAGE_CREATE' => sub {
    my (@events, @messages);
    my $ready;

    my $gw = Disperl::Gateway->new(
        token      => 't',
        on_event   => sub { push @events, [@_] },
        on_message => sub { push @messages, $_[0] },
        on_ready   => sub { $ready = $_[0] },
    );

    $gw->_handle({
        op => 0, t => 'READY', s => 1,
        d  => {
            session_id         => 'sess-1',
            resume_gateway_url => 'wss://resume.example',
            user               => { id => '9', username => 'disperl' },
        },
    });

    is $gw->session_id, 'sess-1', 'session id stored';
    is $gw->user->{username}, 'disperl', 'bot user stored';
    is $ready->{session_id}, 'sess-1', 'on_ready called';

    $gw->_handle({
        op => 0, t => 'MESSAGE_CREATE', s => 2,
        d  => { id => '42', content => 'hello', channel_id => '999' },
    });

    is scalar @messages, 1, 'on_message called';
    is $messages[0]{content}, 'hello', 'message content';

    is scalar @events, 2, 'on_event called for both';
    is $events[1][0], 'MESSAGE_CREATE', 'event name';
};

subtest 'identify payload' => sub {
    my $fake = FakeWS->new;
    my $gw = Disperl::Gateway->new(token => 'secret', intents => [qw(GUILDS GUILD_MESSAGES)]);

    $gw->_identify($fake);

    my $msg = $json->decode($fake->sent->[0]);
    is $msg->{op}, 2, 'op 2';
    is $msg->{d}{token}, 'secret', 'token is raw (no "Bot " prefix)';
    is $msg->{d}{intents}, 513, 'intents';
    is $msg->{d}{properties}{browser}, 'disperl', 'properties';
};

subtest 'resume payload' => sub {
    my $fake = FakeWS->new;
    my $gw = Disperl::Gateway->new(token => 'secret');
    $gw->{session_id} = 'sess-1';
    $gw->{seq}        = 7;

    $gw->_resume($fake);

    my $msg = $json->decode($fake->sent->[0]);
    is $msg->{op}, 6, 'op 6';
    is $msg->{d}{session_id}, 'sess-1', 'session id';
    is $msg->{d}{seq}, 7, 'sequence';
};

subtest 'control ops' => sub {
    my $fake = FakeWS->new;
    my $gw = Disperl::Gateway->new(token => 't');
    $gw->{ws} = $fake;
    $gw->{seq} = 3;

    $gw->_handle({ op => 1 });
    my $hb = $json->decode($fake->sent->[0]);
    is $hb->{op}, 1, 'heartbeat sent';
    is $hb->{d}, 3, 'heartbeat carries the sequence';
    is $gw->{awaiting_ack}, 1, 'waiting for ACK';

    $gw->_handle({ op => 11 });
    is $gw->{awaiting_ack}, 0, 'ACK clears the flag';

    is $gw->_handle({ op => 7 }), 'resume', 'op 7 asks for resume';
    is $gw->_handle({ op => 9 }), 'invalid_session', 'op 9 asks for re-identify';
};

subtest 'run_once: hello, identify, ready, message, close' => sub {
    my (@messages);
    my $ready;

    my $fake = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        frame({
            op => 0, t => 'READY', s => 1,
            d  => {
                session_id         => 'sess-1',
                resume_gateway_url => 'wss://resume.example',
                user               => { id => '9' },
            },
        }),
        frame({ op => 0, t => 'MESSAGE_CREATE', s => 2, d => { content => 'hello' } }),
        { opcode => 8, code => 1000, reason => 'bye' },
    ]);
    $FakeWS::INSTANCE = $fake;
    $FakeWS::LAST_URL = undef;

    my $gw = Disperl::Gateway->new(
        token      => 'secret',
        ws_class   => 'FakeWS',
        reconnect  => 0,
        on_message => sub { push @messages, $_[0] },
        on_ready   => sub { $ready = $_[0] },
    );

    my $reason = $gw->_run_once;

    is $reason, 'resume', 'close leads to a reconnect decision';
    is $FakeWS::LAST_URL, 'wss://gateway.discord.gg/?v=10&encoding=json', 'default URL';

    my $identify = $json->decode($fake->sent->[0]);
    is $identify->{op}, 2, 'identify first';
    is $identify->{d}{intents}, 513, 'default intents';

    is $ready->{session_id}, 'sess-1', 'ready dispatched';
    is $messages[0]{content}, 'hello', 'message dispatched';
    is $fake->{closed}, 1000, 'socket closed';
};

subtest 'run_once: resumes when a session exists' => sub {
    my $fake = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        { opcode => 8, code => 1000 },
    ]);
    $FakeWS::INSTANCE = $fake;
    $FakeWS::LAST_URL = undef;

    my $gw = Disperl::Gateway->new(
        token     => 'secret',
        ws_class  => 'FakeWS',
        reconnect => 0,
    );
    $gw->{session_id}  = 'sess-1';
    $gw->{seq}         = 5;
    $gw->{resume_next} = 1;
    $gw->{resume_url}  = 'wss://resume.example';

    $gw->_run_once;

    is $FakeWS::LAST_URL, 'wss://resume.example?v=10&encoding=json', 'resume URL';
    my $resume = $json->decode($fake->sent->[0]);
    is $resume->{op}, 6, 'resume instead of identify';
    is $resume->{d}{seq}, 5, 'sequence sent';
};

subtest 'run_once: resumes from a saved session' => sub {
    my $fake = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        { opcode => 8, code => 1000 },
    ]);
    $FakeWS::INSTANCE = $fake;

    my $gw = Disperl::Gateway->new(
        token          => 'secret',
        ws_class       => 'FakeWS',
        reconnect      => 0,
        resume_session => { session_id => 'sess-old', seq => 42 },
    );

    my $reason = $gw->_run_once;

    is $FakeWS::LAST_URL, 'wss://gateway.discord.gg/?v=10&encoding=json',
        'no resume URL yet, so the default URL';
    my $resume = $json->decode($fake->sent->[0]);
    is $resume->{op}, 6, 'resumes with the saved session';
    is $resume->{d}{session_id}, 'sess-old', 'saved session id';
    is $resume->{d}{seq}, 42, 'saved seq';
    is $gw->session_id, 'sess-old', 'session id restored';
    is $gw->seq, 42, 'seq restored';
};

subtest 'resume_session and on_session validation' => sub {
    eval {
        Disperl::Gateway->new(
            token => 't', resume_session => { session_id => 's' },
        );
    };
    like $@, qr/resume_session must be a hash reference with session_id and seq/,
        'seq is required';

    eval { Disperl::Gateway->new(token => 't', resume_session => 'x') };
    like $@, qr/resume_session must be a hash reference/, 'type check';

    eval { Disperl::Gateway->new(token => 't', on_session => 'x') };
    like $@, qr/on_session must be a code reference/, 'callback type';
};

subtest 'on_session fires on ready, events and resumed' => sub {
    my @saved;
    my $gw = Disperl::Gateway->new(
        token      => 't',
        on_session => sub { push @saved, { %{ $_[0] } } },
    );

    $gw->_handle({ op => 0, t => 'READY', s => 1, d => { session_id => 's1' } });
    is_deeply $saved[0], { session_id => 's1', seq => 1 }, 'saved on READY';

    $gw->_handle({ op => 0, t => 'MESSAGE_CREATE', s => 2, d => { id => '1' } });
    is_deeply $saved[1], { session_id => 's1', seq => 2 }, 'saved per event';

    # セッションが無い間（起動直後など）は呼ばれない
    my @quiet;
    my $fresh = Disperl::Gateway->new(
        token      => 't',
        on_session => sub { push @quiet, $_[0] },
    );
    $fresh->_handle({ op => 0, t => 'MESSAGE_CREATE', s => 5, d => {} });
    is scalar @quiet, 0, 'not called before a session exists';

    # RESUMED でも通知される
    $gw->_handle({ op => 0, t => 'RESUMED', s => 3, d => {} });
    is_deeply $saved[2], { session_id => 's1', seq => 3 }, 'saved on RESUMED';

    # on_session が die しても処理は続く
    my $broken = Disperl::Gateway->new(
        token      => 't',
        on_session => sub { die "boom\n" },
    );
    $broken->_handle({ op => 0, t => 'READY', s => 1, d => { session_id => 's2' } });
    is $broken->session_id, 's2', 'callback errors do not break dispatch';
};

subtest 'fatal close code is not retried' => sub {
    my $fake = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        { opcode => 8, code => 4004, reason => 'Authentication failed.' },
    ]);
    $FakeWS::INSTANCE = $fake;

    my $gw = Disperl::Gateway->new(token => 'bad', ws_class => 'FakeWS', reconnect => 0);

    eval { $gw->_run_once };
    like $@, qr/Fatal gateway close code 4004/, 'dies with the close code';
};

subtest 'run does not retry fatal close codes' => sub {
    my $fake = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        { opcode => 8, code => 4004 },
    ]);
    $FakeWS::INSTANCE = $fake;

    my @errors;
    my $gw = Disperl::Gateway->new(
        token     => 'bad',
        ws_class  => 'FakeWS',
        reconnect => 1,
        on_error  => sub { push @errors, $_[0] },
    );

    $gw->run;

    is scalar @errors, 1, 'reported once';
    is scalar @{ $fake->sent }, 1, 'identified only once';
};

subtest 'zombie connection triggers a resume' => sub {
    my $fake = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 1 } }),
    ]);
    $FakeWS::INSTANCE = $fake;

    my $gw = Disperl::Gateway->new(
        token     => 't',
        ws_class  => 'FakeWS',
        reconnect => 0,
        on_error  => sub { },
    );

    my $reason = $gw->_run_once;
    is $reason, 'resume', 'no ACK leads to a resume';
};

subtest 'invalid session payload controls resume' => sub {
    my $gw = Disperl::Gateway->new(token => 't');
    $gw->{session_id}  = 'sess-1';
    $gw->{seq}         = 4;
    $gw->{resume_url}  = 'wss://resume.example';
    $gw->{resume_next} = 1;

    # d が true でも false でも、セッションは破棄して Identify からやり直す
    is $gw->_handle({ op => 9, d => JSON::PP::true }), 'invalid_session', 'op 9 d=true';
    ok !defined $gw->{session_id}, 'session discarded even when d is true';
    ok !defined $gw->{seq}, 'sequence discarded';
    ok !defined $gw->{resume_url}, 'resume url discarded';
    is $gw->{resume_next}, 0, 'identify next time';

    $gw->{session_id} = 'sess-2';
    $gw->{seq}        = 8;
    $gw->{resume_url} = 'wss://resume.example';
    $gw->{resume_next} = 1;

    $gw->_handle({ op => 9, d => JSON::PP::false });
    ok !defined $gw->{session_id}, 'session discarded when d is false';
    ok !defined $gw->{seq}, 'sequence discarded';
    ok !defined $gw->{resume_url}, 'resume url discarded';
    is $gw->{resume_next}, 0, 'identify next time';
};

subtest 'READY and RESUMED reset the failure counter' => sub {
    my $gw = Disperl::Gateway->new(token => 't');

    $gw->{failures} = 3;
    $gw->_handle({
        op => 0, t => 'READY', s => 1,
        d  => { session_id => 'sess-1' },
    });
    is $gw->{failures}, 0, 'READY resets failures';

    $gw->{failures} = 2;
    $gw->_handle({ op => 0, t => 'RESUMED', s => 2, d => {} });
    is $gw->{failures}, 0, 'RESUMED resets failures';
};

subtest 'close 4006 discards the session and identifies again' => sub {
    my $first = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        frame({
            op => 0, t => 'READY', s => 1,
            d  => { session_id => 'sess-1', resume_gateway_url => 'wss://resume.example' },
        }),
        { opcode => 8, code => 4006, reason => 'Session no longer valid.' },
    ]);
    my $second = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        { opcode => 8, code => 1000 },
    ]);
    $FakeWS::INSTANCE = undef;
    @FakeWS::CONNECTIONS = ($first, $second);

    my $gw = Disperl::Gateway->new(
        token     => 'secret',
        ws_class  => 'FakeWS',
        reconnect => 0,
    );

    is $gw->_run_once, 'resume', 'asks for a reconnect';
    ok !defined $gw->{session_id}, 'session discarded';
    ok !defined $gw->{seq}, 'sequence discarded';
    is $gw->{resume_next}, 0, 'identify on the next connection';

    $gw->_run_once;

    my $msg = $json->decode($second->sent->[0]);
    is $msg->{op}, 2, 'identify instead of resume';

    @FakeWS::CONNECTIONS = ();
};

subtest 'close 4008 waits before reconnecting' => sub {
    my $first = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        { opcode => 8, code => 4008, reason => 'Rate limited.' },
    ]);
    my $second = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        { opcode => 8, code => 4004 },
    ]);
    $FakeWS::INSTANCE = undef;
    @FakeWS::CONNECTIONS = ($first, $second);

    my (@waits, @errors);
    my $gw = Disperl::Gateway->new(
        token           => 'secret',
        ws_class        => 'FakeWS',
        reconnect       => 1,
        reconnect_delay => 7,
        sleep           => sub { push @waits, $_[0] },
        on_error        => sub { push @errors, $_[0] },
    );

    $gw->run;

    is_deeply \@waits, [7], 'waited reconnect_delay seconds';
    is scalar @errors, 1, 'fatal close reported';
    is scalar @{ $second->sent }, 1, 'reconnected once';

    @FakeWS::CONNECTIONS = ();
};

subtest 'a successful READY allows further reconnects' => sub {
    # 1回目は Hello が来ずエラー、2回目は READY で復帰、3回目はまたエラー。
    # max_reconnects = 1 でも、READY で failures が戻るので停止しない。
    my $first = FakeWS->new(queue => []);
    my $second = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        frame({ op => 0, t => 'READY', s => 1, d => { session_id => 'sess-1' } }),
        { opcode => 8, code => 1000 },
    ]);
    my $third = FakeWS->new(queue => []);
    my $fourth = FakeWS->new(queue => [
        frame({ op => 10, d => { heartbeat_interval => 60000 } }),
        { opcode => 8, code => 4004 },
    ]);
    $FakeWS::INSTANCE = undef;
    @FakeWS::CONNECTIONS = ($first, $second, $third, $fourth);

    my @errors;
    my $gw = Disperl::Gateway->new(
        token          => 'secret',
        ws_class       => 'FakeWS',
        reconnect      => 1,
        max_reconnects => 1,
        sleep          => sub { },
        on_error       => sub { push @errors, $_[0] },
    );

    $gw->run;

    is scalar @{ $fourth->sent }, 1, 'kept reconnecting after a READY';
    is scalar @errors, 3, 'reported the two errors and the fatal close';

    @FakeWS::CONNECTIONS = ();
};

subtest 'max_message_size is passed to the WebSocket' => sub {
    $FakeWS::INSTANCE = undef;
    @FakeWS::CONNECTIONS = (
        FakeWS->new(queue => [ { opcode => 8, code => 4004 } ]),
        FakeWS->new(queue => [ { opcode => 8, code => 4004 } ]),
    );

    my $gw = Disperl::Gateway->new(
        token            => 'secret',
        ws_class         => 'FakeWS',
        max_message_size => 1024,
        on_error         => sub { },
        sleep            => sub { },
    );
    eval { $gw->_run_once };
    is $FakeWS::LAST_ARGS->{max_message_size}, 1024, 'forwarded to connect';

    my $default = Disperl::Gateway->new(
        token    => 'secret',
        ws_class => 'FakeWS',
        on_error => sub { },
        sleep    => sub { },
    );
    eval { $default->_run_once };
    ok !exists $FakeWS::LAST_ARGS->{max_message_size},
        'not passed when unset (WebSocket default applies)';

    @FakeWS::CONNECTIONS = ();
};

done_testing;
