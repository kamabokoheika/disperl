use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use utf8;

use Disperl::Fun qw(omikuji eight_ball love);

# ブロックを実行して、die したメッセージを返す（die しなければ空文字）。
sub exception (&) {
    my ($code) = @_;
    my $ok = eval { $code->(); 1 };
    return '' if $ok;
    my $err = $@ || 'unknown error';
    $err =~ s/\s+\z//;
    return $err;
}

subtest 'omikuji' => sub {
    like omikuji(), qr/^(大吉|吉|中吉|小吉|凶|大凶)\z/, 'random fortune is valid';

    # 種を渡すと決定的（同じ種なら同じ運勢）
    is omikuji('2026-11-23'), omikuji('2026-11-23'), 'same seed, same fortune';
    is omikuji('マタタビ'), omikuji('マタタビ'), 'japanese seed works too';

    # 多数の種で全ての運勢が出ることを確認
    my %seen;
    $seen{ omikuji($_) }++ for 0 .. 199;
    is_deeply [ sort keys %seen ], [ sort qw(大吉 吉 中吉 小吉 凶 大凶) ],
        'all fortunes appear over many seeds';

    is exception { omikuji('') },
        'seed must be a non-empty string', 'empty seed is rejected';
};

subtest 'eight_ball' => sub {
    like eight_ball(), qr/^[🟢🟡🔴]/, 'random answer has a colored marker';

    # 質問を渡すと決定的（同じ質問には同じ答え）
    is eight_ball('今日は勝てる?'), eight_ball('今日は勝てる?'),
        'same question, same answer';
    is eight_ball('テスト'), eight_ball('テスト'), 'japanese question works too';

    my @answers = map { eight_ball("質問$_") } 0 .. 30;
    my %unique = map { $_ => 1 } @answers;
    ok scalar(keys %unique) > 1, 'answers vary across questions';

    for my $answer (@answers) {
        like $answer, qr/^[🟢🟡🔴]/, 'answer is from the list';
    }
};

subtest 'love' => sub {
    my $percent = love('ネコ', 'イヌ');
    like $percent, qr/^\d+\z/, 'returns a number';
    cmp_ok $percent, '>=', 0, 'percent >= 0';
    cmp_ok $percent, '<=', 100, 'percent <= 100';

    # 決定的: 同じペアは常に同じ数字
    is love('ネコ', 'イヌ'), $percent, 'deterministic';

    # 順序不変
    is love('イヌ', 'ネコ'), $percent, 'order does not matter';

    # 日本語 / 英数字どちらでも動く
    like love('nuko', 'kamaboko'), qr/^\d+\z/, 'ascii names work';

    # 違うペアは違う値になりがち（全く同じにはならないことの確認）
    my %values = map { love(@$_) => 1 } (['a', 'b'], ['c', 'd'], ['e', 'f'], ['g', 'h']);
    ok scalar(keys %values) >= 2, 'different pairs tend to differ';

    # 境界は数ペア確認すれば十分
    for my $i (0 .. 5) {
        my $v = love("u$i", "w$i");
        cmp_ok $v, '>=', 0, "pair $i lower bound";
        cmp_ok $v, '<=', 100, "pair $i upper bound";
    }

    is exception { love(undef, 'x') },
        'love requires two non-empty names', 'missing name1 is rejected';
    is exception { love('x', '') },
        'love requires two non-empty names', 'empty name2 is rejected';
};

done_testing;
