# disperl

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Perl](https://img.shields.io/badge/perl-5.20%2B-blue)
![AI generated](https://img.shields.io/badge/AI%20generated-102%25-purple)

> [!IMPORTANT]
> **このプロジェクトは AI によって 102% 作成されています**
> （コード・テスト・ドキュメント・サンプル・この README を含むすべて）。
> **AI が作ったプロジェクトを使いたくない方は、本リポジトリの利用を非推奨とします。**
>
> - 開発の方針決定・動作確認は人間のオーナーが行っていますが、
>   コードを書いているのは AI です。ドキュメント（`docs/` 以下）も AI 生成です
> - ネットワーク不要のテスト（49 ファイル / 481 件）を用意していますが、**無保証**です。
>   本番運用の前にご自身の環境で確認してください
> - ライセンス: [MIT](LICENSE)
> - Issue / PR は歓迎しますが、対応も AI が行うことがあります

Perl 製の Discord Bot 向けライブラリです。REST API と Gateway（WebSocket）の両方を扱えます。

- 追加モジュールなしで動く REST クライアント（core のみ）
- レート制限・リトライ・multipart 添付を内蔵
- Gateway でイベント受信（Identify / Resume / Heartbeat / 自動再接続）
- ボタン・モーダル・オートコンプリート・スラッシュコマンドに対応

詳しいリファレンスは [`docs/`](docs/README.md) にあります。この README は「まず動かす」ための入口です。
順を追って試すなら [チュートリアル](docs/tutorial.md)、やりたいことから探すなら [逆引き](docs/cookbook.md) へ。

## 目次

- [特徴](#特徴)
- [必要環境](#必要環境)
- [セットアップ](#セットアップ)
- [クイックスタート](#クイックスタート)
- [モジュール構成](#モジュール構成)
- [ドキュメント](#ドキュメント)
- [よく使う操作](#よく使う操作)
- [CLI](#cli)
- [テスト](#テスト)
- [注意事項](#注意事項)
- [実装範囲](#実装範囲)

## 特徴

- メッセージの送信・編集・削除・取得、embeds、返信、リアクション、入力中表示
- ファイル添付（最大 10 個。multipart を自前で送信。追加依存なし）
- ネイティブ投票（Poll）の作成・終了・投票者取得
- ピン留め、一括削除、スレッド、DM、招待、Webhook
- スレッドの一覧・参加・退出・メンバー管理・アーカイブ
- フォーラム / メディアへの投稿（本文・embed・コンポーネント・添付・タグ・レイアウト設定）
- チャンネルの作成・編集・並び替え・権限上書き・削除
- 絵文字・ステッカー・サウンドボードの管理（ギルド）
- ステージインスタンスの開始・変更・終了
- アプリ情報・コマンド権限の上書き・ギルド widget / プレビュー / バニティ URL
- ギルド設定の変更・ウェルカム画面・オンボーディング
- Entitlements / SKU / Subscriptions（課金）
- ロール連携メタデータ（Linked Roles）
- メンバー審査・ギルド連携・ギルドテンプレート・ボイスリージョン・一括 BAN
- 権限のサーバー側計算（ギルド / チャンネル / ロール）・ボイスステート
- 招待のターゲットユーザー（Community Invites）・コマンド単体取得
- チャンネルフォロー・ボイスステータス・アナウンスのクロスポスト
- Bot プロフィール（名前 / アイコン / バナー）の変更・アプリ設定の変更・所属ギルドの管理
- メッセージのステッカー・nonce（重複検知）・返信の `fail_if_not_exists`
- ロールの取得・作成・編集・並び替え・削除（色 / アイコン / Unicode 絵文字）
- メンバーの一覧・検索・ニックネーム変更・ロール付与 / 剥奪・タイムアウト
- キック・BAN / BAN 解除・BAN 一覧・プルーン
- 監査ログの取得（実行者 / 種別 / 期間で絞り込み）とイベント名の変換
- AutoMod ルールの作成・取得・変更・削除（キーワード / スパム / メンション / プロフィール）
- スケジュールイベント（ボイス / ステージ / 外部）の作成・変更・削除・参加者取得
- 権限名とビットマスクの相互変換・実効権限の計算（`Disperl::Permissions`）
- レート制限（バケット単位・429）対応と事前スロットリング。5xx は指数バックオフでリトライ
- Gateway（WebSocket）でイベントを受信。Identify / Resume / Heartbeat / 自動再接続
- イベント別コールバック（`on_guild_member_add` など）・member chunking・シャーディング
- ゾンビ接続の検出・指数バックオフ再接続・コールバックのエラー隔離（落ちても接続維持）
- ステータス（online / idle / dnd / invisible）とアクティビティの変更
- ボタン／セレクトメニュー（`Disperl::Components`）とインタラクション応答
- Components V2（Container / Section / Text Display / Media Gallery / File / モーダル V2）
- モーダル（入力フォーム）とオートコンプリート
- スラッシュコマンドの登録と受信
- インタラクションルーター（`Disperl::Router`）でコマンド・ボタン・モーダル・オートコンプリートを振り分け
- HTTP インタラクション（`Disperl::HttpInteractions`）で Ed25519 署名検証・PING 応答。Gateway なしで受信
  （検証エンジンは `Crypt::PK::Ed25519`。HTTP サーバー部分は core のみ）
- Webhook Events（`Disperl::EventWebhooks`）でインストール・Entitlement などの通知を HTTP で受信
- 小ネタ（`Disperl::Fun`）: おみくじ・8ball・好感度診断。プレゼンス文のローテーターも同梱
- Gateway タイマー（`every` / `after`）で定期処理を run ループに直結
- コマンド定義ビルダー（`command` / `option`）と差分同期（`sync_commands`）
- OAuth2 認可コードフロー（PKCE 対応。`Disperl::OAuth2`）でトークン取得・更新・失効

## 必要環境

- Perl 5.20 以降（動作確認は Strawberry Perl 5.42.3 / 64bit ポータブル版）
- `Disperl::Client` は core モジュールのみ
  （`HTTP::Tiny` / `JSON::PP` / `Encode` / `Time::HiRes`）
- `Disperl::Gateway` は `IO::Socket::SSL` を使用
  （Strawberry Perl に同梱。HTTPS を使う時点で実質必須）
- `Disperl::HttpInteractions` の署名検証は `Crypt::PK::Ed25519`（CryptX）を使用
  （内蔵 HTTP サーバー部分は core のみ。`verifier` で検証処理を差し替え可）
- テストは `Test::More`（core）のみ
  （Ed25519 のテストは `Crypt::PK::Ed25519` が無い環境ではスキップ）

Windows で管理者権限が無い場合は、Strawberry Perl のポータブル版を
ASCII のみのパスに置き、`c\bin` を `PATH` に追加してください。

## セットアップ

`.env` を作ります（`.gitignore` 済み）。テンプレートは `.env.example`。

```sh
cp .env.example .env
```

```sh
# .env
DISCORD_TOKEN=トークン          # "Bot " は付けない（コード側で付与）
DISCORD_CHANNEL_ID=送信先チャンネル ID
```

| 変数 | 説明 |
|---|---|
| `DISCORD_TOKEN` | Bot トークン（必須） |
| `DISCORD_CHANNEL_ID` | 送信先チャンネル ID（必須） |
| `DISCORD_APPLICATION_ID` | アプリケーション ID（省略可。未指定なら Bot のユーザー ID） |

優先順位は **実環境変数 > `.env`** です。CI や本番では `.env` を置かず、環境変数だけ設定すれば動きます。

> `.env` やトークンは絶対にコミットしないでください。漏えいした場合は
> Discord Developer Portal でトークンを再生成してください。

書式（BOM / CRLF / クォート / `export`）は [設定](docs/config.md) を参照してください。

## クイックスタート

```perl
use FindBin;
use lib "$FindBin::Bin/lib";
use Disperl::Config qw(load_dotenv);
use Disperl::Client;

load_dotenv("$FindBin::Bin/.env");    # 既存の環境変数は上書きしない

my $client  = Disperl::Client->new(token => $ENV{DISCORD_TOKEN});
my $channel = $ENV{DISCORD_CHANNEL_ID};

# 事前チェック（トークンとチャンネルが有効か）
my $me = $client->get_current_user or die "bad token\n";
my $ch = $client->get_channel($channel) or die "bad channel\n";

my $message = $client->send_message($channel, 'こんにちは');
if ($message) {
    print "sent: $message->{id}\n";

    my $edited = $client->edit_message($channel, $message->{id}, '編集しました');
    print "edited: $edited->{content}\n" if $edited;

    $client->delete_message($channel, $message->{id});
} else {
    my $err = $client->last_error;    # { status, code, message }
    warn "$err->{status} $err->{message}\n";
}
```

- 成功時はハッシュ / 配列 / `1`、失敗時は `undef`。詳細は `last_error`
- 引数不足や上限超過は**送信前に `die`**（API エラーとは別）
- 動くサンプル（送信・embed・ファイル・投票・Gateway・コマンド・モーダル・OAuth2 など）は [`examples/`](examples/README.md) にあります

## モジュール構成

| モジュール | 役割 |
|---|---|
| `Disperl::Client` | REST API。送信・取得・スレッド・チャンネル・ロール・メンバー・イベント・添付・インタラクション応答・コマンド登録 |
| `Disperl::Gateway` | Gateway（WebSocket）。イベント受信・プレゼンス・インタラクション配送 |
| `Disperl::Voice` | 音声接続（voice gateway v8）。RTP 送信・E2EE（DAVE）対応 |
| `Disperl::Voice::Dave` | Discord の E2EE（DAVE）。MLS（RFC 9420）+ AES-128-GCM（純 Perl） |
| `Disperl::Components` | ボタン／セレクト／Components V2／モーダルのビルダー |
| `Disperl::Permissions` | 権限名とビットマスクの相互変換・実効権限の計算 |
| `Disperl::AuditLog` | 監査ログのイベント種別（名前と数値の変換） |
| `Disperl::AutoMod` | AutoMod のトリガー / アクション / プリセット種別 |
| `Disperl::Forum` | フォーラム / メディアのレイアウト・並び順・タグの検証 |
| `Disperl::Fun` | おみくじ・8ball・好感度診断などの小ネタ関数 |
| `Disperl::Sticker` | ステッカーの種別・画像形式 |
| `Disperl::Stage` | ステージインスタンスの公開範囲 |
| `Disperl::Commands` | コマンド / オプション定義のビルダー・検証・差分計算・コマンド権限の対象種別 |
| `Disperl::Router` | インタラクションのルーター（コマンド / コンポーネント / モーダル / オートコンプリート） |
| `Disperl::HttpInteractions` | Interactions Endpoint URL の受信（Ed25519 署名検証・PING 応答・内蔵サーバー）。署名検証は `Crypt::PK::Ed25519`（CryptX）、`verifier` で差し替え可 |
| `Disperl::EventWebhooks` | Webhook Events の受信（インストール・Entitlement などの通知）。検証とサーバーは HttpInteractions と共通 |
| `Disperl::OAuth2` | 認可コードフロー（PKCE）・トークン交換 / 更新 / 失効 |
| `Disperl::Guild` | ギルド設定・オンボーディングの種別 |
| `Disperl::Entitlement` | Entitlement / SKU の種別 |
| `Disperl::RoleConnection` | ロール連携メタデータの種別 |
| `Disperl::Integration` | ギルド連携の種別 |
| `Disperl::WebSocket` | RFC 6455 クライアント（Gateway が使用） |
| `Disperl::Config` | `.env` ローダー |

## ドキュメント

| ページ | 内容 |
|---|---|
| [チュートリアル](docs/tutorial.md) | はじめての Bot（送信 → ボタン → Gateway → コマンド） |
| [逆引き](docs/cookbook.md) | やりたいことからメソッドを探す |
| [実行サンプル](examples/README.md) | 送信・embed・ファイル・投票・Gateway・コマンド・モーダル・OAuth2 の動く例 |
| [Client](docs/client.md) | コンストラクタ・戻り値・エラー・レート制限 |
| [ページネーション](docs/pagination.md) | `each_*` で一覧を自動で辿る |
| [メッセージ](docs/messages.md) | embed・コンポーネント・添付ファイル・投票 |
| [スレッド](docs/threads.md) | 作成・一覧・参加・メンバー・アーカイブ |
| [フォーラム / メディア](docs/forums.md) | 投稿の作成・本文・添付・タグ・レイアウト設定 |
| [チャンネル管理](docs/channels.md) | 作成・編集・並び替え・権限上書き・削除 |
| [絵文字 / ステッカー / サウンドボード](docs/emojis-stickers.md) | ギルドの絵文字・ステッカー・サウンドの管理 |
| [ステージインスタンス](docs/stage.md) | ステージの開始・取得・変更・終了 |
| [アプリ情報 / コマンド権限 / widget](docs/applications.md) | アプリ情報・権限上書き・widget・プレビュー・バニティ |
| [ギルド設定](docs/guild-settings.md) | ギルド設定・ウェルカム画面・オンボーディング |
| [ギルド管理（審査・連携・所属）](docs/guild-admin.md) | メンバー審査・連携・ボイスリージョン・一括 BAN・所属ギルド |
| [Entitlements / SKU](docs/entitlements.md) | 課金・Entitlement・SKU・サブスクリプション |
| [ロール連携メタデータ](docs/role-connections.md) | Linked Roles のメタデータ設定 |
| [OAuth2 / ユーザー連携](docs/oauth2.md) | 認可コード + PKCE・トークン交換 / 更新 / 失効・連携アカウント・ロール連携 |
| [ロール管理](docs/roles.md) | 取得・作成・編集・並び替え・削除・色とアイコン |
| [メンバー管理](docs/members.md) | 一覧・検索・変更・ロール付与・キック / BAN・プルーン・実効権限 |
| [監査ログ](docs/audit-log.md) | 取得・絞り込み・ページング・イベント種別・変更内容 |
| [AutoMod](docs/automod.md) | ルールの作成・取得・変更・削除・トリガー・アクション |
| [スケジュールイベント](docs/events.md) | 作成・変更・削除・参加者 |
| [ギルド・ユーザー・招待](docs/guilds.md) | ギルド情報・メンバー・DM・招待 |
| [Webhook](docs/webhooks.md) | 実行・管理・送信済みメッセージ |
| [インタラクション](docs/interactions.md) | ボタン・モーダル・オートコンプリート・コマンド登録 |
| [コマンド定義](docs/commands.md) | `command` / `option` のビルダー・検証・差分同期 |
| [インタラクションルーター](docs/router.md) | コマンド・ボタン・モーダル・オートコンプリートの振り分け |
| [HTTP インタラクション](docs/http-interactions.md) | Interactions Endpoint URL での受信（Ed25519 署名・PING 応答） |
| [Webhook Events](docs/event-webhooks.md) | イベントの HTTP 受信（インストール・Entitlement・Social SDK 系） |
| [小ネタ](docs/fun.md) | おみくじ・8ball・好感度診断（`Disperl::Fun`） |
| [Gateway](docs/gateway.md) | 接続・イベント・Intent・プレゼンス・再接続 |
| [コンポーネント](docs/components.md) | ボタン・セレクト・モーダルの組み立て |
| [設定](docs/config.md) | `.env` の書式と優先順位 |
| [CLI](docs/cli.md) | `test.pl` の全コマンド |
| [制限値](docs/limits.md) | 送信前に検証される上限 |
| [トラブルシューティング](docs/troubleshooting.md) | 症状別の対処 |
| [用語集](docs/glossary.md) | Discord API の用語 |

## よく使う操作

### embed と添付

```perl
# embed
$client->send_message($channel, undef, {
    embeds => [{ title => '通知', description => '本文', color => 0x5865F2 }],
});

# ファイル添付（最大 10 個）
$client->send_file($channel, 'memo.txt', content => 'ログです');
$client->send_files($channel, ['a.txt', 'b.png'], content => '2 ファイル');
```

### 投票

```perl
my $poll = $client->send_message($channel, undef, {
    poll => { question => 'どちらが好き?', answers => [ '犬', '猫' ], duration => 24 },
});

my $ended = $client->end_poll($channel, $poll->{id});
```

### スレッド

```perl
my $thread = $client->create_thread($channel, name => '議題', type => 'public');
$client->send_message($thread->{id}, '最初の書き込み');
```

### フォーラム / メディア

```perl
my $post = $client->create_forum_post(
    $forum_id,
    name         => 'はじめまして',
    content      => '自己紹介します',
    applied_tags => [ $tag_id ],
);

# メディアチャンネルは添付つきで
$client->create_forum_post($media_id, name => 'スクリーンショット', files => ['shot.png']);
```

詳細は [フォーラム / メディア](docs/forums.md) を参照してください。

### チャンネルとスケジュールイベント

```perl
my $channel = $client->create_guild_channel(
    $guild_id, name => '雑談', type => 'text', topic => '気軽にどうぞ',
);
$client->edit_channel_permissions($channel->{id}, $role_id,
    deny => ['SEND_MESSAGES'],
);

my $event = $client->create_scheduled_event(
    $guild_id,
    name                 => '定例会',
    entity_type          => 'external',
    scheduled_start_time => '2026-12-01T20:00:00Z',
    scheduled_end_time   => '2026-12-01T22:00:00Z',
    location             => 'Discord',
);
```

詳細は [チャンネル管理](docs/channels.md) と [スケジュールイベント](docs/events.md) を参照してください。

### ロールとメンバー

```perl
# ロールを作る
my $role = $client->create_guild_role(
    $guild_id,
    name        => 'モデレーター',
    permissions => ['VIEW_CHANNEL', 'MANAGE_MESSAGES'],
    color       => '#5865F2',
    hoist       => 1,
);

# 付与・剥奪
$client->add_guild_member_role($guild_id, $user_id, $role->{id});
$client->remove_guild_member_role($guild_id, $user_id, $role->{id});

# タイムアウト（ISO8601、undef で解除）
$client->modify_guild_member($guild_id, $user_id,
    communication_disabled_until => '2026-12-01T20:00:00Z');

# キック / BAN
$client->kick_guild_member($guild_id, $user_id, reason => '規約違反');
$client->ban_guild_member($guild_id, $user_id, delete_message_seconds => 86400);
```

```perl
# 実効権限（チャンネル上書き込み）
use Disperl::Permissions qw(channel_permissions permission_names);

my $guild   = $client->get_guild($guild_id);
my $member  = $client->get_guild_member($guild_id, $user_id);
my $channel = $client->get_channel($channel_id);

my $bits = channel_permissions($guild, $member, $channel);
print "$_\n" for permission_names($bits);
```

詳細は [ロール管理](docs/roles.md) と [メンバー管理](docs/members.md) を参照してください。

### 監査ログ

```perl
use Disperl::AuditLog qw(audit_action_name);

my $log = $client->get_guild_audit_log(
    $guild_id,
    action_type => 'MEMBER_KICK',
    limit       => 20,
);

my %users = map { $_->{id} => $_ } @{ $log->{users} || [] };
for my $entry (@{ $log->{audit_log_entries} || [] }) {
    my $user = $users{ $entry->{user_id} // '' } || {};
    printf "%s: %s -> %s\n",
        audit_action_name($entry->{action_type}) // $entry->{action_type},
        $user->{username} // $entry->{user_id} // '?',
        $entry->{target_id} // '-';
}
```

`before` / `after` でページングできます。詳細は [監査ログ](docs/audit-log.md) を参照してください。

### AutoMod

```perl
my $rule = $client->create_guild_automod_rule(
    $guild_id,
    name         => 'スパム対策',
    trigger_type => 'KEYWORD',
    trigger_metadata => {
        keyword_filter => ['spam', 'crypto'],
        regex_patterns => ['https?://\\S+'],
    },
    actions => [
        { type => 'BLOCK_MESSAGE',
          metadata => { custom_message => '宣伝は禁止です' } },
        { type => 'SEND_ALERT_MESSAGE',
          metadata => { channel_id => $log_channel_id } },
    ],
    enabled => 1,
);

$client->update_guild_automod_rule($guild_id, $rule->{id}, enabled => 0);
$client->delete_guild_automod_rule($guild_id, $rule->{id});
```

詳細は [AutoMod](docs/automod.md) を参照してください。

### Webhook

```perl
$client->execute_webhook($id, $token, '通知です', username => 'disperl');
```

### スラッシュコマンドとボタン

```perl
use Disperl::Components qw(action_row button);
use JSON::PP;

$client->register_guild_commands($app_id, $guild_id, [
    { name => 'ping', description => 'pong を返します' },
]);

$client->send_message($channel, '押してください', {
    components => [
        action_row(button(style => 'success', label => 'はい', custom_id => 'yes')),
    ],
});
```

応答は Gateway の `on_command` / `on_component` で受けます。

```perl
my $gw = Disperl::Gateway->new(
    token      => $ENV{DISCORD_TOKEN},
    intents    => [qw(GUILDS GUILD_MESSAGES MESSAGE_CONTENT)],
    on_command => sub {
        my $i = shift;
        $client->reply_interaction($i->{id}, $i->{token}, 'pong', ephemeral => 1);
    },
);

$gw->run;
```

コマンド定義と振り分けをまとめるなら、`Disperl::Commands` と `Disperl::Router` を使います。

```perl
use Disperl::Commands qw(command option);
use Disperl::Router;

my @commands = (
    command(name => 'ping', description => 'pong を返します'),
    command(
        name        => 'echo',
        description => '本文をそのまま返します',
        options     => [
            option(name => 'text', description => '本文', type => 'string', required => 1),
        ],
    ),
);

$client->sync_commands($app_id, \@commands, guild_id => $guild_id);

my $router = Disperl::Router->new(client => $client);
$router->command(ping => sub { $_[0]->reply('pong', ephemeral => 1) });
$router->command(echo => sub { $_[0]->reply($_[0]->option('text')) });

my $gw = Disperl::Gateway->new(
    token   => $ENV{DISCORD_TOKEN},
    intents => [qw(GUILDS)],
    router  => $router,
);

$gw->run;
```

詳しくは [コマンド定義](docs/commands.md) と [インタラクションルーター](docs/router.md) を参照してください。

## CLI

`test.pl` はそのまま使える確認用 CLI です。

```sh
perl test.pl check                 # トークン / Gateway / チャンネル / ギルド / 権限の確認
perl test.pl send "こんにちは"
perl test.pl embed
perl test.pl history 20
perl test.pl upload memo.txt "本文"
perl test.pl poll "質問" --answer はい --answer いいえ
perl test.pl thread --private "相談"
perl test.pl threads
perl test.pl channel-create "告知" --type announcement
perl test.pl role-create "モデレーター" --permissions VIEW_CHANNEL,MANAGE_MESSAGES --color "#5865F2" --hoist
perl test.pl member-role-add <ユーザーID> <ロールID>
perl test.pl prune --days 7                  # 対象人数を確認
perl test.pl member-perms <ユーザーID> --channel <チャンネルID>
perl test.pl audit-log --action MEMBER_KICK --limit 20
perl test.pl audit-log --actions              # イベント種別の一覧
perl test.pl automod                          # AutoMod ルール一覧
perl test.pl automod-create "スパム対策" --trigger KEYWORD --keyword spam --block
perl test.pl event-create "定例会" --start 2026-12-01T20:00:00Z --end 2026-12-01T22:00:00Z --location Discord
perl test.pl commands              # /ping /echo /poll /form を登録
perl test.pl commands --sync       # 差分だけを反映（--keep で削除しない）
perl test.pl watch                 # Gateway で受信
```

全コマンドは [CLI](docs/cli.md) を参照してください。

## テスト

```sh
prove -l t
```

- ネットワーク不要（`ua` と WebSocket を偽オブジェクトに差し替え）
- `t/` から `.env` は読みません
- `Makefile.PL` は不要です。`prove -l t` と `perl test.pl` で完結します

## 注意事項

### Privileged Intents

- `MESSAGE_CONTENT`（`1 << 15`）は **Privileged Intent** です。
  Developer Portal の Bot 設定で有効にしないと `msg->{content}` が空になります
- `GUILD_MEMBERS` / `GUILD_PRESENCES` も Privileged Intent です
- メンバー一覧系の API は `GUILD_MEMBERS` が有効な Bot でないと制限されます

Intent の一覧は [Gateway](docs/gateway.md#intent) にあります。

### Windows

- Strawberry Perl の `c\bin` を PATH に入れていないと
  `IO::Socket::SSL` が `Can't load .../SSLeay.xs.dll` で落ちます
- Perl は日本語を含むパスからスクリプトを開けないことがあります。
  ASCII のみのパスに clone するか、ジャンクション経由で実行してください
- コンソールは cp932 のことが多いため、`test.pl` は実際のコードページに合わせて出力します。
  `DISPERL_CONSOLE_ENCODING=UTF-8` で上書きできます（引数は `DISPERL_ARG_ENCODING`、既定 cp932）
- `.env` は UTF-8（BOM なし推奨、BOM 付きも可）で保存してください

その他の症状は [トラブルシューティング](docs/troubleshooting.md) を参照してください。

## 実装範囲

### 対応済み

- メッセージ: 送信・編集・削除・取得・履歴・返信・embeds（上限を送信前に検証）・TTS
- リアクション・入力中・ピン留め・一括削除
- ファイル添付（最大 10 個をまとめて送信）
- ネイティブ投票（作成・終了・投票者取得）
- スレッド: 作成・一覧・参加・退出・メンバー・アーカイブ・削除
- フォーラム / メディア: 投稿・タグ・本文の埋め込み / コンポーネント / 添付・レイアウト設定（`Disperl::Forum`）
- チャンネル: 作成・編集・並び替え・権限上書き・削除・招待一覧
- 絵文字 / ステッカー / サウンドボード: ギルドの絵文字・ステッカー・サウンドの CRUD（`Disperl::Sticker`）
- ステージインスタンス: 開始・取得・変更・終了（`Disperl::Stage`）
- アプリ情報・コマンド権限・ギルド widget / プレビュー / バニティ URL（`Disperl::Commands`）
- ギルド設定の変更・ウェルカム画面・オンボーディング（`Disperl::Guild`）
- Entitlements / SKU / Subscriptions（`Disperl::Entitlement`）
- ロール連携メタデータ（`Disperl::RoleConnection`）
- メンバー審査・ギルド連携・ギルドテンプレート・ボイスリージョン・一括 BAN・所属ギルド管理（`Disperl::Integration`）
- 権限のサーバー側計算（ギルド / チャンネル / ロール）・ボイスステートの取得 / 変更
- 招待のターゲットユーザー（Community Invites）・コマンド単体の作成 / 編集 / 取得
- ピン留め（新 API）・ギルド内メッセージ検索・インシデントアクション・ロールのメンバー数
- サブスクリプション単体取得・サウンドボード再生・Slack / GitHub 互換 Webhook
- OAuth2: 認可コード + PKCE（`Disperl::OAuth2`）・クライアントクレデンシャルズ・Bearer エンドポイント・グループ DM・OAuth2 メンバー追加
- Activities: アクティビティインスタンス・`LAUNCH_ACTIVITY`（type 12）
- チャンネルフォロー・ボイスステータス・Bot プロフィール変更・アプリ編集
- メッセージ小物: ステッカー・nonce・クロスポスト・リアクション単位の削除・元の応答の取得 / 削除・ステッカーパック取得
- ページネーション（`each_message` / `each_guild_member` / `each_guild_ban` / `each_audit_log_entry`）
- `send_message` / `edit_message` への添付統合（`files` / `files_data`）・添付メタデータの自動生成・MIME 表の拡充
- ロール: 取得・作成・編集・並び替え・削除・色 / アイコン / Unicode 絵文字
- メンバー: 一覧・検索・ニックネーム・ロール付与 / 剥奪・タイムアウト・キック / BAN / プルーン
- 権限: 名前とビットマスクの相互変換・実効権限の計算（`Disperl::Permissions`）
- 監査ログ: 取得・実行者 / 種別 / 期間での絞り込み・イベント名の変換（`Disperl::AuditLog`）
- AutoMod: ルールの作成・取得・変更・削除・トリガー / アクションの検証（`Disperl::AutoMod`）
- スケジュールイベント: 一覧・取得・作成・変更・削除・参加者
- DM・ギルド情報の取得・招待・Webhook 実行（ファイル添付可）
- Webhook の管理と送信済みメッセージの取得・編集・削除
- Gateway: Identify / Resume / Heartbeat / 再接続 / プレゼンス / 型付きコールバック / member chunking / シャーディング / capabilities
- インタラクション: ボタン・セレクト・モーダル・オートコンプリート・フォローアップ
- HTTP インタラクション: Interactions Endpoint URL での受信（Ed25519 署名検証・PING 応答・`Disperl::HttpInteractions`。
  検証は `Crypt::PK::Ed25519`（CryptX）、HTTP サーバー部分は core のみ）
- Webhook Events: イベントの HTTP 受信（インストール・Entitlement・Social SDK 系通知・`Disperl::EventWebhooks`）
- Components V2: Container / Section / Text Display / Media Gallery / File / Separator / モーダル V2
- スラッシュコマンド: 登録・一覧・削除（ギルド / グローバル）
- レート制限: バケット単位・major parameter・429 / 5xx リトライ

### 未対応

- 音声（Voice）接続
- ギルドの作成 / 削除（ユーザーアカウントの操作）
- ユーザーアプリ / 埋め込みアプリ
