# Disperl::Gateway

Discord Gateway（WebSocket）に接続してイベントを受信します。
Identify / Resume / Heartbeat / 自動再接続 / プレゼンス変更に加え、
型付きコールバック・メンバー一括取得・シャーディングに対応しています。

## 目次

- [基本的な受信](#基本的な受信)
- [コンストラクタ](#コンストラクタ)
- [コールバック](#コールバック)
- [型付きコールバック](#型付きコールバック)
- [メンバー一括取得](#メンバー一括取得)
- [シャーディング](#シャーディング)
- [capabilities](#capabilities)
- [Intent](#intent)
- [再接続](#再接続)
- [セッションの保存と復元](#セッションの保存と復元)
- [プレゼンス](#プレゼンス)
- [タイマー](#タイマー)
- [関連ページ](#関連ページ)

## 基本的な受信

```perl
use Disperl::Client;
use Disperl::Gateway;

my $client = Disperl::Client->new(token => $ENV{DISCORD_TOKEN});

my $gw = Disperl::Gateway->new(
    token   => $ENV{DISCORD_TOKEN},
    intents => [qw(GUILDS GUILD_MESSAGES MESSAGE_CONTENT)],
    on_message => sub {
        my $msg = shift;
        return if $msg->{author}{bot};          # Bot 自身は無視
        $client->send_message($msg->{channel_id}, "echo: $msg->{content}");
    },
);

$gw->run;    # stop() が呼ばれるまでブロックする
```

## コンストラクタ

| 引数 | 既定値 | 説明 |
|---|---|---|
| `token` | （必須） | Bot トークン。`Bot ` を付けない生の値 |
| `intents` | `GUILDS \| GUILD_MESSAGES` (513) | 整数、または名前の配列 |
| `on_event` | — | `sub { my ($type, $data, $raw) = @_ }` 全イベント |
| `on_message` | — | `MESSAGE_CREATE` のときだけ |
| `on_interaction` | — | `INTERACTION_CREATE` のときだけ（全 type） |
| `on_command` | — | type 2（スラッシュコマンド）だけ |
| `on_component` | — | type 3（ボタン / セレクト）だけ |
| `on_autocomplete` | — | type 4（オートコンプリート）だけ |
| `on_modal` | — | type 5（モーダル送信）だけ |
| `router` | — | `Disperl::Router`。インタラクション系のコールバックをまとめて設定（[ルーター](router.md)） |
| `on_ready` | — | `READY` のときだけ |
| `on_error` | 未指定なら `warn` | 接続エラー・再接続の通知 |
| `shard` | — | `[id, count]`（[シャーディング](#シャーディング)） |
| `capabilities` | — | 整数、または名前の配列（[capabilities](#capabilities)） |
| 型付き | — | `on_guild_create` / `on_message_update` など（[型付きコールバック](#型付きコールバック)） |
| `reconnect` | `1` | 自動再接続するか |
| `resume_session` | — | 前回の `{ session_id, seq }`。最初の接続で Resume から始める（[セッションの保存と復元](#セッションの保存と復元)） |
| `on_session` | — | `sub { my ($session) = @_ }`。READY / RESUMED と `seq` が進む各イベントで呼ばれる |
| `max_reconnects` | `5` | 連続エラーの上限（READY でリセット） |
| `reconnect_delay` | `5` | 4008（レート制限）で再接続するまでの待ち秒 |
| `error_backoff` | `1` | エラー再接続の指数バックオフの基準秒 |
| `max_backoff` | `30` | エラー再接続の待ち時間の上限（秒） |
| `timeout` | `60` | 受信のタイムアウト秒 |
| `max_message_size` | 32 MiB | 受信メッセージの上限（バイト）。`0` で無制限 |
| `url` | `wss://gateway.discord.gg/?v=10&encoding=json` | 接続先 |
| `ws_class` | `Disperl::WebSocket` | 差し替え可能（テスト用） |
| `sleep` | `sub { sleep $_[0] }` | 再接続待ちのフック（テスト用） |
| `status` | 未指定なら Discord の既定 | `online` / `idle` / `dnd` / `invisible` / `offline` |
| `activity` | — | 文字列、または `{ type => ..., name => ... }` |
| `activities` | — | アクティビティの配列（複数指定用） |
| `afk` | `0` | AFK 状態にするか |
| `since` | `null` | アイドルになった時刻（Unix ミリ秒）。`0` で null |
| `presence_interval` | `4` | プレゼンス更新の最小間隔（秒） |

参照用アクセサ:

| メソッド | 内容 |
|---|---|
| `$gw->intents` | 現在の Intent ビットマスク |
| `$gw->session_id` | セッション ID（READY 後） |
| `$gw->seq` | 現在のシーケンス番号（イベントを受けるたびに進む） |
| `$gw->application_id` | アプリケーション ID（READY 後） |
| `$gw->user` | Bot 自身のユーザー情報（READY 後） |
| `$gw->is_running` | `run` 中か |
| `$gw->presence` | 現在のプレゼンス（未設定なら `undef`） |
| `$gw->shard` | シャード `[id, count]`（未設定なら `undef`） |
| `$gw->capabilities` | capabilities のビットマスク（未設定なら `undef`） |

`stop()` でループを止められます。

送信系の操作:

| メソッド | 説明 |
|---|---|
| `$gw->request_guild_members($guild_id, %opts)` | メンバーを要求（op 8、[メンバー一括取得](#メンバー一括取得)） |
| `$gw->request_soundboard_sounds(@guild_ids)` | サウンドボード音源を要求（op 31）。結果は `on_soundboard_sounds` |
| `$gw->request_channel_info($guild_id, @fields)` | チャンネルの一時情報を要求（op 43）。`fields` は `status` / `voice_start_time` |
| `$gw->set_presence(%args)` | プレゼンスを変更 |

## コールバック

`on_event` は**すべての** Dispatch イベントで呼ばれます。個別のコールバックと併用できます。

```perl
my $gw = Disperl::Gateway->new(
    token    => $ENV{DISCORD_TOKEN},
    on_event => sub {
        my ($type, $data, $raw) = @_;
        print "event: $type\n";
    },
    on_message => sub { ... },
);
```

`INTERACTION_CREATE` では `on_interaction` が先に呼ばれ、その後 type に応じて
`on_command` / `on_component` / `on_autocomplete` / `on_modal` が呼ばれます
（同じイベントで複数のコールバックが動く点に注意）。

`router` を渡すと、この 4 つのコールバックがルーターに接続されます。
個別の `on_*` を明示した場合はそちらが優先されます。

## 型付きコールバック

イベント名ごとのコールバックをコンストラクタに渡せます。
引数は `($data, $raw)` です（`$raw` は `op` / `t` / `s` を含む生メッセージ）。

```perl
my $gw = Disperl::Gateway->new(
    token          => $ENV{DISCORD_TOKEN},
    intents        => [qw(GUILDS GUILD_MEMBERS GUILD_MESSAGES)],
    on_message     => sub { ... },
    on_message_update => sub {
        my ($data, $raw) = @_;
        print "edited: $data->{id}\n";
    },
    on_guild_member_add => sub {
        my ($data) = @_;
        print "joined: $data->{user}{username}\n";
    },
);
```

| コールバック | イベント |
|---|---|
| `on_message` / `on_message_update` / `on_message_delete` / `on_message_delete_bulk` | `MESSAGE_*` |
| `on_reaction_add` / `on_reaction_remove` / `on_reaction_remove_all` / `on_reaction_remove_emoji` | `MESSAGE_REACTION_*` |
| `on_poll_vote_add` / `on_poll_vote_remove` | `MESSAGE_POLL_VOTE_*` |
| `on_typing_start` | `TYPING_START` |
| `on_guild_create` / `on_guild_update` / `on_guild_delete` | `GUILD_*` |
| `on_guild_member_add` / `on_guild_member_update` / `on_guild_member_remove` | `GUILD_MEMBER_*` |
| `on_guild_members_chunk` | `GUILD_MEMBERS_CHUNK` |
| `on_guild_ban_add` / `on_guild_ban_remove` | `GUILD_BAN_*` |
| `on_guild_role_create` / `on_guild_role_update` / `on_guild_role_delete` | `GUILD_ROLE_*` |
| `on_guild_emojis_update` / `on_guild_stickers_update` | `GUILD_EMOJIS_UPDATE` / `GUILD_STICKERS_UPDATE` |
| `on_guild_integrations_update` / `on_integration_create` / `on_integration_update` / `on_integration_delete` | `GUILD_INTEGRATIONS_UPDATE` / `INTEGRATION_*` |
| `on_channel_create` / `on_channel_update` / `on_channel_delete` | `CHANNEL_*` |
| `on_channel_info` / `on_channel_pins_update` | `CHANNEL_INFO` / `CHANNEL_PINS_UPDATE` |
| `on_thread_create` / `on_thread_update` / `on_thread_delete` | `THREAD_*` |
| `on_thread_list_sync` / `on_thread_member_update` / `on_thread_members_update` | `THREAD_LIST_SYNC` / `THREAD_MEMBER*_UPDATE` |
| `on_invite_create` / `on_invite_delete` | `INVITE_*` |
| `on_presence_update` | `PRESENCE_UPDATE` |
| `on_voice_state_update` | `VOICE_STATE_UPDATE` |
| `on_voice_channel_status_update` / `on_voice_channel_start_time_update` / `on_voice_channel_effect_send` | `VOICE_CHANNEL_*` |
| `on_soundboard_sound_create` / `on_soundboard_sound_update` / `on_soundboard_sound_delete` / `on_soundboard_sounds_update` | `GUILD_SOUNDBOARD_SOUND_*` |
| `on_soundboard_sounds` | `SOUNDBOARD_SOUNDS` |
| `on_scheduled_event_create` / `on_scheduled_event_update` / `on_scheduled_event_delete` | `GUILD_SCHEDULED_EVENT_*` |
| `on_scheduled_event_user_add` / `on_scheduled_event_user_remove` | `GUILD_SCHEDULED_EVENT_USER_*` |
| `on_automod_action` | `AUTO_MODERATION_ACTION_EXECUTION` |
| `on_automod_rule_create` / `on_automod_rule_update` / `on_automod_rule_delete` | `AUTO_MODERATION_RULE_*` |
| `on_entitlement_create` / `on_entitlement_update` / `on_entitlement_delete` | `ENTITLEMENT_*` |
| `on_subscription_create` / `on_subscription_update` / `on_subscription_delete` | `SUBSCRIPTION_*` |
| `on_command_permissions_update` | `APPLICATION_COMMAND_PERMISSIONS_UPDATE` |
| `on_audit_log_entry_create` | `GUILD_AUDIT_LOG_ENTRY_CREATE` |

- 型付きコールバックを用意していないイベントは無視されます（`on_event` は全イベントで呼ばれます）
- `READY` / `RESUMED` / `INTERACTION_CREATE` は専用のコールバック（`on_ready` など）が動きます
- 型付きコールバックは `on_event` より先に呼ばれます

## メンバー一括取得

`GUILD_MEMBERS`（Privileged Intent）を有効にすると、メンバー一覧を要求できます。
結果は `GUILD_MEMBERS_CHUNK` として `on_guild_members_chunk` に届きます。

```perl
# コールバックの中から $gw を使うので、先に宣言しておく
my $gw;
$gw = Disperl::Gateway->new(
    token   => $ENV{DISCORD_TOKEN},
    intents => [qw(GUILDS GUILD_MEMBERS)],
    on_guild_members_chunk => sub {
        my ($data) = @_;
        print "$data->{guild_id}: ",
            scalar(@{ $data->{members} || [] }), " members\n";
    },
    on_ready => sub {
        $gw->request_guild_members($guild_id);                 # 全件（limit 0）
        $gw->request_guild_members($guild_id, query => 'kama'); # 名前で検索
        $gw->request_guild_members($guild_id, presets => ['online']);
        $gw->request_guild_members($guild_id, user_ids => [$id1, $id2]);
    },
);

$gw->run;
```

| キー | 説明 |
|---|---|
| （省略） | 全メンバーを要求（`limit => 0`） |
| `query` | ユーザー名 / ニックネームで絞り込む |
| `limit` | 0〜100。`0` は全件 |
| `presets` | `online` / `offline` の配列 |
| `user_ids` | 特定ユーザーの配列（最大 100） |
| `nonce` | チャンクに付ける任意の文字列 |

- 接続前や未 READY の状態で呼ぶと `die` します
- 大量取得はレート制限の対象です。1 ギルド 1 回程度に留めてください

## シャーディング

大規模な Bot ではシャードを分けて接続します。`shard => [id, count]` を渡すと
Identify に `shard` が含まれます。

```perl
my $gw = Disperl::Gateway->new(
    token   => $ENV{DISCORD_TOKEN},
    shard   => [ 0, 2 ],          # 2 シャード中の 0 番目
    intents => [qw(GUILDS GUILD_MESSAGES)],
);

print @{ $gw->shard };            # 0 2
```

- `id` は `0` 以上 `count - 1` 以下。範囲外は `die`
- 推奨シャード数は `$client->get_gateway_bot->{shards}` で確認できます
- CLI では `perl test.pl watch --shard 0/2` で指定できます

## capabilities

`capabilities` は Identify に含める別のビットフィールドで、
**接続の振る舞い**を切り替えます（`intents` は受信イベントの選択）。

```perl
my $gw = Disperl::Gateway->new(
    token        => $ENV{DISCORD_TOKEN},
    capabilities => ['CHANNEL_OBFUSCATION'],   # または 1 << 15 の整数
);

print $gw->capabilities;    # 32768

# 名前からビットマスクを作る
my $bits = Disperl::Gateway->capability_bits('CHANNEL_OBFUSCATION');
```

| 名前 | 値 | 説明 |
|---|---|---|
| `CHANNEL_OBFUSCATION` | `1 << 15` | 権限の無いチャンネルのメタデータを秘匿して受信する（テスト用のオプトイン） |

- 未指定なら Identify に `capabilities` を含めません
- CLI では `perl test.pl watch --capabilities CHANNEL_OBFUSCATION` で指定できます

## Intent

`intents` は整数ビットマスクか、名前の配列で指定します。
名前からビットを作るには `intent_bits` を使います。

```perl
my $bits = Disperl::Gateway->intent_bits(qw(GUILDS MESSAGE_CONTENT));

my $gw = Disperl::Gateway->new(
    token   => $ENV{DISCORD_TOKEN},
    intents => $bits,
);
```

| 名前 | ビット | 備考 |
|---|---|---|
| `GUILDS` | `1 << 0` | |
| `GUILD_MEMBERS` | `1 << 1` | **Privileged** |
| `GUILD_MODERATION` | `1 << 2` | |
| `GUILD_EMOJIS_AND_STICKERS` | `1 << 3` | |
| `GUILD_INTEGRATIONS` | `1 << 4` | |
| `GUILD_WEBHOOKS` | `1 << 5` | |
| `GUILD_INVITES` | `1 << 6` | |
| `GUILD_VOICE_STATES` | `1 << 7` | |
| `GUILD_PRESENCES` | `1 << 8` | **Privileged** |
| `GUILD_MESSAGES` | `1 << 9` | |
| `GUILD_MESSAGE_REACTIONS` | `1 << 10` | |
| `GUILD_MESSAGE_TYPING` | `1 << 11` | |
| `DIRECT_MESSAGES` | `1 << 12` | |
| `DIRECT_MESSAGE_REACTIONS` | `1 << 13` | |
| `DIRECT_MESSAGE_TYPING` | `1 << 14` | |
| `MESSAGE_CONTENT` | `1 << 15` | **Privileged** |
| `GUILD_SCHEDULED_EVENTS` | `1 << 16` | |

- 既定は `GUILDS | GUILD_MESSAGES`（513）
- `MESSAGE_CONTENT` が無いと `$msg->{content}` は空になる
- Privileged Intent は Developer Portal の Bot 設定で有効化が必要

## 再接続

`run` は接続が切れるたびに次を判断して再接続します。

| 状況 | 動作 |
|---|---|
| 正常な切断 / Resume 可能 | Resume（`op 6`）で再開 |
| `4006` / `4007` / `4009` | セッションを破棄して Identify からやり直す |
| Invalid Session（Resume 不可） | 1〜5 秒待ってからやり直す |
| `4008`（レート制限） | `reconnect_delay` 秒待ってから再接続 |
| `4004` / `4010`〜`4014` | **再接続しない**（トークン・Intent 不正） |
| Heartbeat の ACK が返らない | ゾンビ接続とみなして再接続 |
| `op 7`（Reconnect） | 再接続 |

- 連続失敗回数は READY / RESUMED で 0 に戻る
- 失敗が `max_reconnects` を超えると `run` は戻る（`die` はしない）
- エラー時の再接続待ちは**指数バックオフ**: `error_backoff * 2^(失敗回数-1)`、上限 `max_backoff`
- 汎用クローズとゾンビ検出は **1 秒待ってから** Resume（即時再接続の繰り返しを防ぐ）
- WebSocket のマスクキーは `/dev/urandom` → `Crypt::URandom` の順で確保（無い環境はハッシュ混合）
- `reconnect => 0` で自動再接続を無効化
- Resume 時は READY で受け取った `resume_gateway_url` を使う
- 初回 Heartbeat は `heartbeat_interval` の範囲でランダムにずらす

エラーは `on_error` に文字列で渡されます（未指定なら `warn`）。
`on_error => sub {}` で無音にできます。`on_error` 自体が `die` しても接続は維持されます。

### コールバックのエラー隔離

`on_message` などのコールバックが `die` しても、接続は切れません。
`on_error` に `Error in on_message callback: ...` の形で渡され、後続のイベントは処理され続けます。

```perl
my $gw = Disperl::Gateway->new(
    token      => $ENV{DISCORD_TOKEN},
    on_message => sub { die "boom\n" },
    on_error   => sub { warn "handler error: $_[0]\n" },
);
```

## セッションの保存と復元

プロセスを再起動したあとでも、前回のセッションを Resume できます。
`on_session` で `session_id` と `seq` を保存し、次回起動時に
`resume_session` として渡します。

```perl
my $state = "$FindBin::Bin/gateway-state.json";

my $saved;
if (-f $state) {
    $saved = decode_json(do { local $/; open my $fh, '<:raw', $state; <$fh> });
}

my $gw = Disperl::Gateway->new(
    token   => $ENV{DISCORD_TOKEN},
    intents => [qw(GUILDS)],
    # イベントごとに呼ばれるので、保存処理は軽く保つこと
    on_session     => sub {
        my ($session) = @_;    # { session_id => ..., seq => ... }
        open my $fh, '>:raw', $state;
        print {$fh} encode_json($session);
        close $fh;
    },
    resume_session => $saved,    # 無ければ undef で OK（通常の Identify になる）
);
```

- `on_session` は READY / RESUMED と、`seq` が進む各イベントで呼ばれます
- 保存しておいたセッションが無効のときは、自動で Identify からやり直します
  （Invalid Session の扱いは [再接続](#再接続)と同じ）
- 復元できたイベントは Resume 時に Discord が再生します
  （保持期間は限られるので、古いセッションは復元に失敗することがあります）
- `resume_session` は生きているセッションが無い接続でのみ使われます。
  一度 Resume が成功すれば、以降は同じプロセス内の通常の Resume と同じです
- `$gw->session_id` / `$gw->seq` で現在の値を読めます

## プレゼンス

```perl
# 接続時の初期ステータス
my $gw = Disperl::Gateway->new(
    token    => $ENV{DISCORD_TOKEN},
    status   => 'idle',
    activity => '待機中',
);

# 接続中に変更する
$gw->set_presence(status => 'online');
$gw->set_presence(status => 'dnd', activity => '作業中');
$gw->set_presence(status => 'invisible');          # オフライン表示
$gw->set_presence(activity => { type => 'watching', name => '配信' });
$gw->set_presence(activity => []);                 # アクティビティを消す
```

`activity` の `type`:

| 名前 | 数値 |
|---|---|
| `playing` | 0 |
| `streaming` | 1 |
| `listening` | 2 |
| `watching` | 3 |
| `custom` | 4 |
| `competing` | 5 |

```perl
$gw->set_presence(activity => {
    type  => 'custom',
    state => '作業中',
    emoji => { name => '💻' },
});
```

ルール:

- `set_presence` は指定しなかった項目を現在値から引き継ぐ
- 接続前なら次の Identify で、接続中なら READY 後に反映される
- `streaming` は `url` が必須
- `custom` は `state` に表示テキストを入れる（`name` 省略時は `Custom Status`）
- `emoji` はハッシュで渡し、`name` か `id` のどちらかが必要
- 変更は Gateway に接続している間だけ有効。切断すると通常のオフラインに戻る
- Discord の制限（20 秒に 5 回）を超えないよう、既定で 4 秒間隔に間引く
- 間引かれている間の変更は最新の 1 件だけが送られる
- `invisible` は他のユーザーからオフラインに見える（Bot 自体は動作を続ける）
- REST API では変更できない（Gateway の `op 3` を使用）

### プレゼンスのローテーション

`rotate_presence` でプレゼンス文を一定間隔で切り替えられます。

```perl
$gw->rotate_presence(
    messages => ['ﾆｬｰ', 'omikuji で運勢診断', '時給5円'],
    interval => 30,        # 秒（最小 5、既定 30）
    status   => 'idle',    # 省略可
    type     => 'watching' # playing / streaming / listening / watching / competing
);
$gw->run;
```

- `type` の既定は `watching`。各メッセージが「〜を見てる」系のアクティビティになります
- 停止は `$gw->stop_rotate_presence`
- `set_presence` と併用できます（ローテーションが次の tick で上書きします）
- メッセージの送信は内部のレート制限（`presence_interval`）に従います

## タイマー

`every` / `after` で、Gateway の run ループに乗るタイマーを登録できます。
統計のフラッシュ・定期 announce・後処理などを **fork や自前管理なしで**書けます。

```perl
$gw->every(300 => \&flush_stats, name => 'stats');   # 5 分ごと（名前付き）
$gw->every(30  => sub { ... });                      # 無名（自動採番）
$gw->after(10  => sub { ... });                      # 10 秒後に 1 回だけ
$gw->cancel_timer('stats');                          # 名前指定で解除
$gw->cancel_all_timers;                              # 全解除
```

- コールバックは **`$gw` を受け取ります**（`$gw->set_presence` なども呼べます）
- **接続中（READY 後）だけ発火**します。切断中・再接続中はスキップされます
- コールバックが `die` しても `on_error` に流れてループは止まりません（繰り返しタイマーは削除されない）
- 同じ `name` で登録し直すと上書きされるので、`on_ready` 内の冪等セットアップに向いています
- 受信待ちに 1 秒の上限があるため、発火の粒度は約 1 秒です

> **注意**: コールバックが重い（数秒以上）とイベント処理が止まります。
> yt-dlp 解決や AI 呼び出しなどの重い処理は、コールバック内で直接行わず
> **fork して子プロセスに投げてください**（Linux VPS なら fork が最軽量です）。

## 関連ページ

- [チュートリアル](tutorial.md)
- [逆引き](cookbook.md)
- [インタラクション](interactions.md)
- [インタラクションルーター](router.md)
- [メンバー管理](members.md)
- [Client](client.md)
- [トラブルシューティング](troubleshooting.md)
