package Disperl::Fun;
use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

use Exporter 'import';
use Encode ();
use Digest::SHA qw(sha256);

our @EXPORT_OK = qw(omikuji eight_ball love);

# Bot にちょっとした遊び心を足す小ネタ集。
#   use Disperl::Fun qw(omikuji eight_ball love);
#
#   my $fortune  = omikuji();                 # 大吉 〜 大凶（ランダム）
#   my $fortune2 = omikuji('2026-11-23');     # 同じ種なら同じ結果
#   my $answer   = eight_ball();              # ランダムな返答
#   my $answer2  = eight_ball('今日は勝てる?'); # 同じ質問なら同じ返答
#   my $percent  = love('Alice', 'Bob');      # 0〜100 の好感度（順序不変・決定的）
#
# love は名前のペアから決定的に 0〜100 を算出します。
# 同じ名前のペアなら常に同じ数字になるため、「毎回同じ結果が出る」ネタとして使えます。

# おみくじ（重みは合計 100）
my @FORTUNES = (
    [ '大吉' => 15 ],
    [ '吉'   => 25 ],
    [ '中吉' => 20 ],
    [ '小吉' => 20 ],
    [ '凶'   => 15 ],
    [ '大凶' => 5  ],
);

# 8ball の返答（20 種）
my @EIGHT_BALL = (
    "🟢間違いないよ!", "🟢そう決まっているね!", "🟢疑う余地がない!", "🟢絶対YES!!", "🟢頼っていい!",
    "🟢私の見るところではYES!", "🟢ほぼ間違いない!", "🟢見通しは良好ですね", "🟢YES!", "🟢YESの兆し!",
    "🟡ぼんやりしていてわからないよぉ", "🟡後で聞いてね", "🟡今は言えないです", "🟡今は予測できないなぁ", "🟡集中してもう一度聞いてね",
    "🔴期待しないほうがいいよぉ", "🔴私の答えはNOです", "🔴情報源によるとNOだってさ", "🔴見通しは良くないなぁ", "🔴非常に怪しいなぁ",
);

# おみくじを引く。引数なしでランダム、文字列を渡すと決定的になる。
#   omikuji()          # ランダム
#   omikuji('2026-11-23')  # 同じ種なら常に同じ運勢
sub omikuji {
    my ($seed) = @_;

    my $roll = defined $seed ? _seeded_int($seed, 100) : int(rand(100));

    my $acc = 0;
    for my $entry (@FORTUNES) {
        $acc += $entry->[1];
        return $entry->[0] if $roll < $acc;
    }

    return $FORTUNES[-1][0];
}

# 8ball。引数なしでランダム、質問を渡すと決定的になる（同じ質問には同じ答え）。
#   eight_ball()
#   eight_ball('今日は勝てる?')
sub eight_ball {
    my ($question) = @_;

    my $count = scalar @EIGHT_BALL;
    my $index = defined $question && length $question
        ? _seeded_int($question, $count)
        : int(rand($count));

    return $EIGHT_BALL[$index];
}

# 好感度を 0〜100 で診断する。名前の順序は結果に影響しない。
#   love('Alice', 'Bob')
sub love {
    my ($name1, $name2) = @_;

    die "love requires two non-empty names\n"
        unless defined $name1 && length $name1
            && defined $name2 && length $name2;

    my @sorted = sort($name1, $name2);
    my $combined = "$sorted[0]&$sorted[1]";
    $combined = Encode::encode('UTF-8', $combined) if utf8::is_utf8($combined);

    # 圧縮アルゴリズム: SHA256 の各バイトを
    # 偶奇で異なる回転 XOR に通して 1 バイトに潰し、101 で割った余りを好感度にする。
    my $value = 0xAA;
    my $index = 0;
    for my $byte (unpack 'C*', sha256($combined)) {
        if ($index % 2 == 0) {
            $value ^= ( ($byte << 3) | ($byte >> 5) ) & 0xFF;
        } else {
            $value ^= ( ($byte >> 2) | ($byte << 6) ) & 0xFF;
        }
        $index++;
    }

    return $value % 101;
}

# 種の文字列から 0 以上 max 未満の整数を作る（決定的）。
sub _seeded_int {
    my ($seed, $max) = @_;

    die "seed must be a non-empty string\n"
        unless defined $seed && length $seed;

    my $bytes = "$seed";
    $bytes = Encode::encode('UTF-8', $bytes) if utf8::is_utf8($bytes);

    return unpack('N', sha256($bytes)) % $max;
}

1;
