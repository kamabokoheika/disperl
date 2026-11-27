use strict;
use warnings;
use utf8;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use JSON::PP;
use Disperl::Gateway;

my $json = JSON::PP->new->utf8(1);

package FakeWS;
sub new { return bless { sent => [] }, shift }
sub send_text { my ($self, $t) = @_; push @{ $self->{sent} }, $t; return 1 }
sub recv_frame { return undef }
sub close      { return 1 }
sub sent       { return $_[0]->{sent} }
package main;

# die したメッセージを返すヘルパー
sub exception (&) {
    my ($code) = @_;
    my $ok = eval { $code->(); 1 };
    return '' if $ok;
    my $err = $@ || 'unknown error';
    $err =~ s/\s+\z//;
    return $err;
}

subtest 'validation' => sub {
    my $gw = Disperl::Gateway->new(token => 't');

    like exception { $gw->every(0    => sub { }) }, qr/interval must be an integer of 1 second or more/, 'zero interval';
    like exception { $gw->every(-1   => sub { }) }, qr/interval must be an integer of 1 second or more/, 'negative interval';
    like exception { $gw->every(0.5  => sub { }) }, qr/interval must be an integer of 1 second or more/, 'fractional interval';
    like exception { $gw->every(5    => 'x' ) },     qr/code must be a code reference/,      'string code';
    like exception { $gw->every(5 => sub {}, name => '') }, qr/timer name must be a non-empty string/,
        'empty name';
    like exception { $gw->after(0    => sub { }) }, qr/interval must be an integer of 1 second or more/, 'after: zero';
    like exception { $gw->cancel_timer },            qr/timer name is required/,             'cancel without name';
};

subtest 'every fires when ready and reschedules' => sub {
    my $gw = Disperl::Gateway->new(token => 't');
    $gw->{ws}    = FakeWS->new;
    $gw->{ready} = 1;

    my @calls;
    ok $gw->every(5 => sub { push @calls, $_[0] }, name => 't1'), 'register';
    is scalar(keys %{ $gw->timers }), 1, 'timer stored';
    ok !$gw->_tick_timers, 'not fired yet (next_at is in the future)';

    $gw->{timers}{t1}{next_at} = 0;
    ok $gw->_tick_timers, 'tick fires the timer';
    is scalar(@calls), 1, 'callback ran once';
    is $calls[0], $gw, 'callback receives the gateway';
    cmp_ok $gw->{timers}{t1}{next_at}, '>=', time() - 1, 'rescheduled to ~now+interval';

    # 接続していないときは発火しない
    $gw->{ready} = 0;
    $gw->{timers}{t1}{next_at} = 0;
    ok !$gw->_tick_timers, 'not ready → no fire';
    is scalar(@calls), 1, 'still one';
    $gw->{ready} = 1;
};

subtest 'timer errors are isolated' => sub {
    my @errors;
    my $gw = Disperl::Gateway->new(token => 't', on_error => sub { push @errors, $_[0] });
    $gw->{ws}    = FakeWS->new;
    $gw->{ready} = 1;

    my $good = 0;
    $gw->every(1 => sub { die "boom\n" }, name => 'bad');
    $gw->every(1 => sub { $good++ },      name => 'good');
    $gw->{timers}{bad}{next_at}  = 0;
    $gw->{timers}{good}{next_at} = 0;

    ok $gw->_tick_timers, 'tick survives a dying timer';
    like $errors[0], qr/timer 'bad'/, 'error reported with the timer name';
    is $good, 1, 'the other timer still ran';

    # 死んだタイマーは削除されない（繰り返し）ので、次もまた発火する
    $gw->{timers}{bad}{next_at}  = 0;
    $gw->{timers}{good}{next_at} = 0;
    ok $gw->_tick_timers, 'next tick still works';
    like $errors[1], qr/timer 'bad'/, 'error reported again';
};

subtest 'after is one-shot' => sub {
    my $gw = Disperl::Gateway->new(token => 't');
    $gw->{ws}    = FakeWS->new;
    $gw->{ready} = 1;

    my @calls;
    $gw->after(1 => sub { push @calls, $_[0] }, name => 'once');
    $gw->{timers}{once}{next_at} = 0;

    ok $gw->_tick_timers, 'fires';
    is scalar(@calls), 1, 'ran once';
    ok !exists $gw->{timers}{once}, 'one-shot timer is removed';
    ok !$gw->_tick_timers, 'no refire';
    is scalar(@calls), 1, 'still one';
};

subtest 'named replace and cancel' => sub {
    my $gw = Disperl::Gateway->new(token => 't');
    $gw->{ws}    = FakeWS->new;
    $gw->{ready} = 1;

    $gw->every(5  => sub { }, name => 'x');
    $gw->every(10 => sub { }, name => 'x');
    is $gw->{timers}{x}{interval}, 10, 'named timer is replaced';
    is scalar(keys %{ $gw->timers }), 1, 'no duplicate';

    # 無名タイマーは自動採番
    $gw->every(1 => sub { });
    ok grep({ /^#\d+\z/ } keys %{ $gw->timers }), 'auto name starts with #';

    ok $gw->cancel_timer('x'), 'cancel x';
    ok !$gw->cancel_timer('x'), 'cancel again returns 0';
    is scalar(keys %{ $gw->timers }), 1, 'only the auto-named one remains';

    is $gw->cancel_all_timers, 1, 'cancel all';
    is scalar(keys %{ $gw->timers }), 0, 'all cleared';
    ok !$gw->cancel_all_timers, 'cancel all again returns 0';

    is_deeply $gw->timers, {}, 'timers is empty';
};

done_testing;
