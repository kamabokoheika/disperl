use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/lib";
use Test::More;
use JSON::PP;
use Disperl::Client;
use Disperl::Gateway;
use FakeUA;

my $json = JSON::PP->new->utf8(1);

# ---------------------------------------------------------------- Client

subtest '5xx の指数バックオフ' => sub {
    my @waits;
    my $fake = FakeUA->new(
        FakeUA->err_response(502, 'bad'),
        FakeUA->err_response(503, 'bad'),
        FakeUA->err_response(504, 'bad'),
    );
    my $client = Disperl::Client->new(
        token => 'dummy', ua => $fake, max_retries => 2,
        retry_backoff => 1, sleep => sub { push @waits, $_[0] },
        on_error => sub { },
    );

    ok !defined $client->send_message('999', 'x'), 'fails';
    is_deeply \@waits, [ 1, 2 ], 'exponential backoff (1s, 2s)';

    @waits = ();
    my $capped = Disperl::Client->new(
        token => 'dummy',
        ua    => FakeUA->new(
            FakeUA->err_response(500, 'x'),
            FakeUA->err_response(500, 'x'),
            FakeUA->err_response(500, 'x'),
        ),
        max_retries => 2, retry_backoff => 10, max_retry_delay => 15,
        sleep => sub { push @waits, $_[0] }, on_error => sub { },
    );
    $capped->send_message('999', 'x');
    is_deeply \@waits, [ 10, 15 ], 'max_retry_delay caps the backoff';

    @waits = ();
    my $fast = Disperl::Client->new(
        token => 'dummy',
        ua    => FakeUA->new(
            FakeUA->err_response(500, 'x'),
            FakeUA->err_response(500, 'x'),
            FakeUA->ok_response($json->encode({ id => '1' })),
        ),
        max_retries => 2, retry_backoff => 0.5,
        sleep => sub { push @waits, $_[0] }, on_error => sub { },
    );
    is $fast->send_message('999', 'x')->{id}, '1', 'recovers after retries';
    is_deeply \@waits, [ 0.5, 1 ], 'custom base backoff';
};

subtest 'last_error の詳細' => sub {
    my $fake = FakeUA->new(FakeUA->err_response(400, $json->encode({
        code    => 50035,
        message => 'Invalid Form Body',
        errors  => {
            content => {
                _errors => [ { code => 'BASE_TYPE_REQUIRED', message => 'required' } ],
            },
        },
    })));
    my $client = Disperl::Client->new(
        token => 'dummy', ua => $fake, on_error => sub { }, max_retries => 0,
    );

    ok !defined $client->send_message('999', 'x'), 'fails';
    my $err = $client->last_error;
    is $err->{code}, 50035, 'code';
    is $err->{message}, 'Invalid Form Body', 'message';
    is ref $err->{errors}, 'HASH', 'errors details';
    like $err->{errors}{content}{_errors}[0]{code}, qr/BASE_TYPE_REQUIRED/,
        'nested error code';
};

subtest 'on_error が die しても呼び出し元は止まらない' => sub {
    my $fake = FakeUA->new(FakeUA->err_response(403, '{"message":"Forbidden"}'));
    my $client = Disperl::Client->new(
        token => 'dummy', ua => $fake,
        on_error => sub { die "handler failed\n" },
        max_retries => 0,
    );

    my @warnings;
    my $msg;
    {
        local $SIG{__WARN__} = sub { push @warnings, @_ };
        $msg = $client->send_message('999', 'x');
    }

    ok !defined $msg, 'returns undef';
    is scalar @warnings, 1, 'warns once';
    like $warnings[0], qr/on_error callback failed: handler failed/,
        'handler failure is reported';
};

# ---------------------------------------------------------------- Gateway

subtest '再接続の待ち時間' => sub {
    my $gw = Disperl::Gateway->new(
        token => 't', error_backoff => 1, max_backoff => 5,
    );

    $gw->{failures} = 1;
    is $gw->_reconnect_wait('error'), 1, 'first error';
    $gw->{failures} = 2;
    is $gw->_reconnect_wait('error'), 2, 'doubles';
    $gw->{failures} = 3;
    is $gw->_reconnect_wait('error'), 4, 'doubles again';
    $gw->{failures} = 4;
    is $gw->_reconnect_wait('error'), 5, 'capped by max_backoff';

    is $gw->_reconnect_wait('rate_limited'), 5, 'rate limit uses reconnect_delay';
    is $gw->_reconnect_wait('resume'), 1, 'generic close waits 1 second';
    is $gw->_reconnect_wait(undef), 0, 'no reason';

    my $wait = $gw->_reconnect_wait('invalid_session');
    ok $wait >= 1 && $wait <= 5, "invalid_session waits 1-5s (got $wait)";

    my $custom = Disperl::Gateway->new(
        token => 't', reconnect_delay => 12, error_backoff => 2, max_backoff => 100,
    );
    $custom->{failures} = 1;
    is $custom->_reconnect_wait('error'), 2, 'custom error_backoff';
    is $custom->_reconnect_wait('rate_limited'), 12, 'custom reconnect_delay';
};

subtest 'コールバックの die を隔離する' => sub {
    my (@errors, @roles, @events);
    my $gw = Disperl::Gateway->new(
        token                => 't',
        on_message           => sub { die "boom\n" },
        on_guild_role_create => sub { push @roles, $_[0]{role}{name} },
        on_event             => sub { push @events, $_[0] },
        on_error             => sub { push @errors, $_[0] },
    );

    $gw->_handle({ op => 0, t => 'MESSAGE_CREATE', s => 1, d => { content => 'x' } });
    is scalar @errors, 1, 'on_error is called';
    like $errors[0], qr/Error in on_message callback: boom/, 'error message';

    # 失敗しても接続や後続イベントは続く
    $gw->_handle({
        op => 0, t => 'GUILD_ROLE_CREATE', s => 2,
        d  => { role => { name => 'new' } },
    });
    is $roles[0], 'new', 'later events still dispatch';
    is scalar @events, 2, 'on_event still fires';

    my @event_errors;
    my $gw2 = Disperl::Gateway->new(
        token              => 't',
        on_typing_start    => sub { die "typing boom\n" },
        on_error           => sub { push @event_errors, $_[0] },
    );
    $gw2->_handle({ op => 0, t => 'TYPING_START', s => 1, d => {} });
    like $event_errors[0], qr/Error in on_typing_start callback: typing boom/,
        'typed callback failure';
};

subtest 'on_error 自体の die も隔離する' => sub {
    my $gw = Disperl::Gateway->new(
        token      => 't',
        on_message => sub { die "boom\n" },
        on_error   => sub { die "handler boom\n" },
    );

    my @warnings;
    my $ok = eval {
        local $SIG{__WARN__} = sub { push @warnings, @_ };
        $gw->_handle({ op => 0, t => 'MESSAGE_CREATE', s => 1, d => {} });
        1;
    };

    ok $ok, 'no exception escapes';
    like $warnings[0], qr/on_error callback failed: handler boom/,
        'handler failure is warned';
};

# ハンドシェイクでフレームが無い / close が来る場合

package FakeNoHello;

sub connect { return bless { sent => [] }, $_[0] }
sub send_text { }
sub recv_frame { return undef }
sub close { }

package FakeCloseDuringHello;

sub connect { return bless { sent => [] }, $_[0] }
sub send_text { }
sub recv_frame {
    return { opcode => 8, code => 4004, reason => 'Authentication failed' };
}
sub close { }

package main;

subtest 'ハンドシェイクのエラー' => sub {
    my $timeout = Disperl::Gateway->new(
        token => 't', ws_class => 'FakeNoHello', timeout => 1,
    );
    my $ok = eval { $timeout->_run_once; 1 };
    ok !$ok, 'dies on timeout';
    like $@, qr/Timed out waiting for Hello \(op 10\)/, 'timeout message';

    my $closed = Disperl::Gateway->new(
        token => 't', ws_class => 'FakeCloseDuringHello', timeout => 1,
    );
    $ok = eval { $closed->_run_once; 1 };
    ok !$ok, 'dies on close';
    like $@, qr/Fatal gateway close code 4004/,
        'close message includes fatal close code';
};

done_testing;
