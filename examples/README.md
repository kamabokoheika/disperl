# examples

すぐ動かせるサンプルです。リポジトリのルートに `.env` を用意してから実行します。

```sh
cp .env.example .env     # DISCORD_TOKEN / DISCORD_CHANNEL_ID を編集
```

## 一覧

| ファイル | 内容 | 追加の準備 |
|---|---|---|
| [send_message.pl](send_message.pl) | メッセージを 1 件送る（REST のみ） | なし |
| [embeds_and_poll.pl](embeds_and_poll.pl) | embed とネイティブ投票を送る（REST のみ） | なし |
| [upload_files.pl](upload_files.pl) | メモリ上のデータを添付して送る（REST のみ） | なし |
| [components_v2.pl](components_v2.pl) | Components V2 でレイアウトしたメッセージを送る（REST のみ） | なし |
| [pagination.pl](pagination.pl) | `each_*` でメッセージ / メンバー一覧を辿る（REST のみ） | なし（ギルド表示は `DISCORD_GUILD_ID`） |
| [forum_post.pl](forum_post.pl) | フォーラムに投稿を作って返信する（REST のみ） | `DISCORD_FORUM_CHANNEL_ID` |
| [oauth2_login.pl](oauth2_login.pl) | OAuth2 認可コード + PKCE でトークンを取得 | `DISCORD_CLIENT_ID`（と Redirect 登録） |
| [http_interactions.pl](http_interactions.pl) | Interactions Endpoint URL の HTTP サーバー（署名検証 / PING 応答） | `DISCORD_PUBLIC_KEY` と公開 URL（トークンがあれば `/hello` にも応答） |
| [fun_bot.pl](fun_bot.pl) | 小ネタコマンドに応答する（おみくじ / 8ball / 好感度）+ プレゼンスローテーター | `MESSAGE_CONTENT`（Privileged Intent）を有効にする |
| [event_webhooks.pl](event_webhooks.pl) | Webhook Events を受信する HTTP サーバー | `DISCORD_PUBLIC_KEY` と公開 URL（イベント購読も必要） |
| [interaction_endpoint.psgi](interaction_endpoint.psgi) | PSGI / Plack で Interactions Endpoint を受ける | `DISCORD_PUBLIC_KEY`。実行には Plack（`plackup`）が必要 |
| [echo_bot.pl](echo_bot.pl) | `!ping` / `!echo` に応答する | `MESSAGE_CONTENT`（Privileged Intent）を有効にする |
| [slash_command.pl](slash_command.pl) | `/ping` を登録して応答する | なし |
| [buttons.pl](buttons.pl) | ボタン付きメッセージを送って応答する | なし |
| [select_menu.pl](select_menu.pl) | セレクトメニューで選択を受け取る | なし |
| [modal_form.pl](modal_form.pl) | `/feedback` でモーダル（入力フォーム）を開く | なし |
| [autocomplete.pl](autocomplete.pl) | `/lang` で入力候補を出す | なし |
| [router_bot.pl](router_bot.pl) | ルーターでコマンド・ボタン・モーダルを振り分ける | なし |

## 実行

```sh
perl examples/send_message.pl      # 1 回だけ送って終了
perl examples/embeds_and_poll.pl
perl examples/upload_files.pl
perl examples/components_v2.pl
perl examples/pagination.pl
perl examples/forum_post.pl
perl examples/oauth2_login.pl
perl examples/http_interactions.pl
perl examples/event_webhooks.pl
plackup examples/interaction_endpoint.psgi
perl examples/fun_bot.pl
perl examples/echo_bot.pl          # Ctrl+C まで動き続ける
perl examples/slash_command.pl
perl examples/buttons.pl
perl examples/select_menu.pl
perl examples/modal_form.pl
perl examples/autocomplete.pl
perl examples/router_bot.pl
```

## .env の変数

| 変数 | 使う例 | 説明 |
|---|---|---|
| `DISCORD_TOKEN` | ほぼ全部 | Bot トークン（`Bot ` は付けない） |
| `DISCORD_CHANNEL_ID` | ほぼ全部 | 送信先チャンネル ID |
| `DISCORD_GUILD_ID` | slash_command / modal_form / autocomplete / pagination | ギルド ID。未設定ならチャンネルから推測 |
| `DISCORD_APPLICATION_ID` | slash_command / modal_form / autocomplete | アプリ ID。未設定なら Bot のユーザー ID |
| `DISCORD_FORUM_CHANNEL_ID` | forum_post | フォーラム / メディアチャンネルの ID |
| `DISCORD_CLIENT_ID` | oauth2_login | OAuth2 のクライアント ID |
| `DISCORD_CLIENT_SECRET` | oauth2_login | OAuth2 のクライアントシークレット（機密クライアントのみ） |
| `DISCORD_OAUTH_REDIRECT_URI` | oauth2_login | 既定 `http://localhost:8080/callback` |
| `DISCORD_PUBLIC_KEY` | http_interactions / event_webhooks | アプリの Public Key（Developer Portal の General Information） |
| `DISCORD_HTTP_PORT` | http_interactions / event_webhooks | 待ち受けポート（既定 8080） |

- Gateway を使う例は `Ctrl+C` で終了します
- `MESSAGE_CONTENT` などの Intent は Discord Developer Portal の Bot 設定で有効にしてください
- トークンやシークレットは `.env` にだけ置いて、コミットしないでください

## 関連

- 順番に学ぶ: [チュートリアル](../docs/tutorial.md)
- やりたいことから探す: [逆引き](../docs/cookbook.md)
- リファレンス: [`docs/`](../docs/README.md)
