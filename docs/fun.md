# 小ネタ（Disperl::Fun）

Bot に遊び心を足す小さな関数集です。`Digest::SHA`（core）以外の依存はありません。
8ball と好感度診断は**決定的**（同じ入力には同じ結果）なのが特徴です。

## 目次

- [おみくじ](#おみくじ)
- [8ball](#8ball)
- [好感度診断](#好感度診断)
- [Bot での使い方](#bot-での使い方)
- [CLI](#cli)
- [関連ページ](#関連ページ)

## おみくじ

```perl
use Disperl::Fun qw(omikuji);

my $fortune = omikuji();             # 大吉 / 吉 / 中吉 / 小吉 / 凶 / 大凶
my $fixed   = omikuji('2026-11-23'); # 同じ種なら常に同じ運勢
```

- 重み: 大吉 15% / 吉 25% / 中吉 20% / 小吉 20% / 凶 15% / 大凶 5%
- 種（任意の文字列）を渡すと決定的になります（「今日の運勢」のように日付を種にすると毎日固定）

## 8ball

```perl
use Disperl::Fun qw(eight_ball);

my $answer = eight_ball();              # ランダムな返答（20 種）
my $answer2 = eight_ball('勝てる?');    # 同じ質問には常に同じ答え
```

- 返答は 🟢（肯定的）/ 🟡（曖昧）/ 🔴（否定的）の 3 系統 20 種
- 質問を渡すと質問のハッシュで答えが固定されます（「同じ質問には同じ答え」の 8ball として使えます）

## 好感度診断

```perl
use Disperl::Fun qw(love);

my $percent = love('Alice', 'Bob');   # 0〜100
```

- 名前を連結した SHA256 を独自に圧縮した値
- **名前の順序を変えても結果は同じ**、同じペアなら常に同じ数字
- 毎回変わる方が好きなら、名前の片方に日付を混ぜるなどの工夫を

## Bot での使い方

動く例は `examples/fun_bot.pl` にあります。
`^omikuji` / `^8ball` / `^love` に応答する前置コマンド Bot の見本でもあります
（`MESSAGE_CONTENT` Intent が必要です）。

```perl
use Disperl::Fun qw(omikuji eight_ball love);

if ($content =~ /^\^omikuji\z/) {
    $client->send_message($channel, '運勢: ' . omikuji());
} elsif ($content =~ /^\^8ball\s+(.+)/s) {
    $client->send_message($channel, eight_ball($1));
} elsif ($content =~ /^\^love\s+(\S+)\s+(\S+)/) {
    $client->send_message($channel, sprintf '%s × %s の好感度: %d%%', $1, $2, love($1, $2));
}
```

## CLI

```sh
perl test.pl fun-omikuji [--seed S]     おみくじ
perl test.pl fun-8ball [質問]           8ball（質問なしはランダム）
perl test.pl fun-love <名前1> <名前2>   好感度診断
```

## 関連ページ

- [Gateway](gateway.md)（プレゼンス文のローテーション）
- [チュートリアル](tutorial.md)
- [CLI](cli.md)
