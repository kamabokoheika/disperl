# disperl ドキュメント

> **Note**: このドキュメントを含め、本プロジェクトは AI によって作成されています
> （詳しくは [README](../README.md) 冒頭の注意書きを参照してください）。

Perl 製の Discord Bot 向けライブラリ **disperl** のリファレンスです。
REST API（`Disperl::Client`）と Gateway / WebSocket（`Disperl::Gateway`）の両方を扱えます。

## モジュール構成

| モジュール | 役割 | 主な依存 |
|---|---|---|
| `Disperl::Client` | REST API。メッセージ・添付・投票・スレッド・チャンネル・ロール・メンバー・イベント・Webhook・インタラクション応答 | core のみ（`HTTP::Tiny` / `JSON::PP` / `Encode`） |
| `Disperl::Gateway` | Gateway 接続。イベント受信・プレゼンス・再接続 | `IO::Socket::SSL` |
| `Disperl::Components` | ボタン / セレクトメニュー / Components V2 / モーダルのビルダー | `JSON::PP` |
| `Disperl::Permissions` | 権限名とビットマスクの相互変換・実効権限の計算 | core のみ |
| `Disperl::AuditLog` | 監査ログのイベント種別（名前と数値の変換） | core のみ |
| `Disperl::AutoMod` | AutoMod のトリガー / アクション / プリセット種別 | core のみ |
| `Disperl::Forum` | フォーラム / メディアのレイアウト・並び順・タグの検証 | core のみ |
| `Disperl::Fun` | おみくじ・8ball・好感度診断などの小ネタ関数 | core のみ |
| `Disperl::Sticker` | ステッカーの種別・画像形式 | core のみ |
| `Disperl::Stage` | ステージインスタンスの公開範囲 | core のみ |
| `Disperl::Commands` | コマンド / オプション定義のビルダー・検証・差分計算・コマンド権限の対象種別 | core のみ |
| `Disperl::Router` | インタラクションのルーター（コマンド / コンポーネント / モーダル / オートコンプリート） | core のみ |
| `Disperl::HttpInteractions` | Interactions Endpoint URL の受信（Ed25519 署名検証・PING 応答・内蔵サーバー） | `Crypt::PK::Ed25519`（CryptX）。検証処理は差し替え可 |
| `Disperl::EventWebhooks` | Webhook Events の受信（インストール・Entitlement などの通知。署名検証・PING 応答） | `Disperl::HttpInteractions` を継承。依存は同じ |
| `Disperl::OAuth2` | 認可コードフロー（PKCE）・トークン交換 / 更新 / 失効 | core のみ |
| `Disperl::Guild` | ギルド設定・オンボーディングの種別 | core のみ |
| `Disperl::Entitlement` | Entitlement / SKU の種別 | core のみ |
| `Disperl::RoleConnection` | ロール連携メタデータの種別 | core のみ |
| `Disperl::Integration` | ギルド連携の種別 | core のみ |
| `Disperl::WebSocket` | RFC 6455 クライアント（Gateway が内部で使用） | `IO::Socket::SSL`（乱数は `Crypt::URandom` を任意で使用） |
| `Disperl::Config` | `.env` ローダー | core のみ |

## ページ一覧

| ページ | 内容 |
|---|---|
| [チュートリアル](tutorial.md) | はじめての Bot（送信 → ボタン → Gateway → コマンド） |
| [逆引き](cookbook.md) | やりたいことからメソッドを探す索引 |
| [Client](client.md) | コンストラクタ・戻り値・エラー・レート制限・基本操作 |
| [ページネーション](pagination.md) | `each_*` で履歴・メンバー・BAN・監査ログを自動で辿る |
| [メッセージ](messages.md) | 本文・embed・コンポーネント・添付ファイル・投票 |
| [スレッド](threads.md) | 作成・一覧・参加・メンバー・アーカイブ |
| [フォーラム / メディア](forums.md) | 投稿の作成・本文・添付・タグ・レイアウト設定 |
| [チャンネル管理](channels.md) | 作成・編集・並び替え・権限上書き・削除 |
| [絵文字 / ステッカー / サウンドボード](emojis-stickers.md) | ギルドの絵文字・ステッカー・サウンドの管理 |
| [ステージインスタンス](stage.md) | ステージの開始・取得・変更・終了 |
| [音声（Voice）](voice.md) | 音声接続・RTP 送信・E2EE（DAVE）・Ogg / Player 音源 |
| [アプリ情報 / コマンド権限 / widget](applications.md) | アプリ情報・権限上書き・widget・プレビュー・バニティ |
| [ギルド設定](guild-settings.md) | ギルド設定・ウェルカム画面・オンボーディング |
| [ギルド管理（審査・連携・所属）](guild-admin.md) | メンバー審査・連携・ボイスリージョン・一括 BAN・所属ギルド |
| [Entitlements / SKU](entitlements.md) | 課金・Entitlement・SKU・サブスクリプション |
| [ロール連携メタデータ](role-connections.md) | Linked Roles のメタデータ設定 |
| [OAuth2 / ユーザー連携](oauth2.md) | 認可コード + PKCE・トークン交換 / 更新 / 失効・連携アカウント・ロール連携 |
| [ロール管理](roles.md) | 取得・作成・編集・並び替え・削除・色とアイコン |
| [メンバー管理](members.md) | 一覧・検索・変更・ロール付与・キック / BAN・プルーン・実効権限 |
| [監査ログ](audit-log.md) | 取得・絞り込み・ページング・イベント種別・変更内容 |
| [AutoMod](automod.md) | ルールの作成・取得・変更・削除・トリガー・アクション |
| [スケジュールイベント](events.md) | 作成・変更・削除・参加者・繰り返し |
| [ギルド・ユーザー・招待](guilds.md) | ギルド情報・メンバー・DM・招待 |
| [Webhook](webhooks.md) | 実行と管理、送信済みメッセージの操作 |
| [インタラクション](interactions.md) | 応答（type 4〜9）・フォローアップ・コマンド登録 |
| [コマンド定義](commands.md) | `command` / `option` のビルダー・検証・差分同期 |
| [インタラクションルーター](router.md) | コマンド・ボタン・モーダル・オートコンプリートの振り分け |
| [HTTP インタラクション](http-interactions.md) | Interactions Endpoint URL での受信（Ed25519 署名・PING 応答） |
| [Webhook Events](event-webhooks.md) | イベントの HTTP 受信（インストール・Entitlement・Social SDK 系） |
| [小ネタ](fun.md) | おみくじ・8ball・好感度診断（`Disperl::Fun`） |
| [Gateway](gateway.md) | 接続・イベント・Intent・プレゼンス・再接続 |
| [コンポーネント](components.md) | ボタン・セレクト・モーダルの組み立て |
| [設定](config.md) | `.env` の読み込みルール |
| [CLI](cli.md) | `test.pl` の全コマンド |
| [制限値](limits.md) | 送信前に検証される上限の一覧 |
| [トラブルシューティング](troubleshooting.md) | よくある失敗と対処 |
| [用語集](glossary.md) | Discord API の用語 |

## 最小例

```perl
use FindBin;
use lib "$FindBin::Bin/lib";
use Disperl::Config qw(load_dotenv);
use Disperl::Client;

load_dotenv("$FindBin::Bin/.env");    # 既存の環境変数は上書きしない

my $client  = Disperl::Client->new(token => $ENV{DISCORD_TOKEN});
my $channel = $ENV{DISCORD_CHANNEL_ID};

my $message = $client->send_message($channel, 'こんにちは');
if ($message) {
    print "sent: $message->{id}\n";
} else {
    my $err = $client->last_error;    # { status, code, message }
    warn "$err->{status} $err->{message}\n";
}
```

## 前提

- Perl 5.20 以降（動作確認は Strawberry Perl 5.42.3）
- Discord API は **v10** を使用
- Bot トークンは `Bot ` を付けずに渡す（`Disperl::Client` が内部で付与）

## 実装範囲

### 対応済み

- メッセージ: 送信・編集・削除・取得・履歴・返信・embed・TTS
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
- メンバー審査・連携（Integrations）・ギルドテンプレート・ボイスリージョン・一括 BAN・所属ギルド管理（`Disperl::Integration`）
- 権限のサーバー側計算（ギルド / チャンネル / ロール）・ボイスステートの取得 / 変更
- 招待のターゲットユーザー（Community Invites）・コマンド単体の作成 / 編集 / 取得
- ピン留め（新 API）・ギルド内メッセージ検索・インシデントアクション・ロールのメンバー数
- ページネーション（`each_message` / `each_guild_member` / `each_guild_ban` / `each_audit_log_entry`）
- `send_message` / `edit_message` への添付統合（`files` / `files_data`）・添付メタデータの自動生成・MIME 表の拡充
- サブスクリプション単体取得・サウンドボード再生・Slack / GitHub 互換 Webhook
- OAuth2: 認可コード + PKCE（`Disperl::OAuth2`）・クライアントクレデンシャルズ・Bearer エンドポイント（連携 / ロール連携）・グループ DM・OAuth2 メンバー追加
- Activities: アクティビティインスタンス・`LAUNCH_ACTIVITY`（type 12）
- Entitlements / SKU / Subscriptions（`Disperl::Entitlement`）
- ロール連携メタデータ（`Disperl::RoleConnection`）
- チャンネルフォロー・ボイスステータス・Bot プロフィール変更・アプリ編集
- メッセージ小物: ステッカー・nonce・クロスポスト・リアクション単位の削除・元の応答の取得 / 削除
- ロール: 取得・作成・編集・並び替え・削除・色 / アイコン / Unicode 絵文字
- メンバー: 一覧・検索・ニックネーム・ロール付与 / 剥奪・タイムアウト・キック / BAN / プルーン
- 権限: 名前とビットマスクの相互変換・実効権限の計算（`Disperl::Permissions`）
- 監査ログ: 取得・実行者 / 種別 / 期間での絞り込み・イベント名の変換（`Disperl::AuditLog`）
- AutoMod: ルールの作成・取得・変更・削除・トリガー / アクションの検証（`Disperl::AutoMod`）
- スケジュールイベント: 一覧・取得・作成・変更・削除・参加者
- DM・ギルド情報・招待
- Webhook: 実行・管理・送信済みメッセージの取得 / 編集 / 削除
- Gateway: Identify / Resume / Heartbeat / 再接続（指数バックオフ・ゾンビ検出） / コールバックのエラー隔離 / プレゼンス / 型付きコールバック / member chunking / シャーディング / capabilities
- インタラクション: ボタン・セレクト・モーダル・オートコンプリート・フォローアップ
- インタラクションルーター: コマンドパス・`custom_id`（完全一致 / 前方一致 / 正規表現）・モーダル・
  オートコンプリート・クールダウン・エラー隔離（`Disperl::Router`）
- HTTP インタラクション: Interactions Endpoint URL での受信。Ed25519 署名検証・PING 応答・
  ルーター委譲・インライン応答・内蔵サーバー（`Disperl::HttpInteractions`）
- Webhook Events: イベントの HTTP 受信。Ed25519 署名検証・PING 応答（204）・
  種別ごとのハンドラ・内蔵サーバー（`Disperl::EventWebhooks`）
- コマンド定義: `command` / `option` ビルダー・型 / choices / ローカライズ / 権限の検証・
  差分同期（`sync_commands`。`Disperl::Commands`）
- Components V2: Container / Section / Text Display / Media Gallery / File / Separator / モーダル V2
- スラッシュコマンド: 登録・一覧・削除（ギルド / グローバル）・差分同期
- レート制限: バケット単位・major parameter・429 / 5xx リトライ（5xx は指数バックオフ）

### 未対応

- ギルドの作成 / 削除（ユーザーアカウントの操作）
- ユーザーアプリ / 埋め込みアプリ

## 関連

- はじめての Bot は [チュートリアル](tutorial.md)
- やりたいことから探すときは [逆引き](cookbook.md)
- 動くサンプルはリポジトリの `examples/` にあります
- リポジトリ直下の `README.md` は「まず動かす」ための入口です
