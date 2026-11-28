# 音声（Voice）接続

音声チャンネルへの参加・RTP 送信・E2EE（DAVE）対応の `Disperl::Voice` を扱います。

- `Disperl::Voice` — voice gateway (v8) のハンドシェイク・RTP 送信・再生制御
- `Disperl::Voice::Dave` — Discord の E2EE（[DAVE](https://github.com/discord/dave-protocol)）。2026-03 以降の VC は E2EE 必須
- `Disperl::Voice::Crypto` — XChaCha20-Poly1305（transport 暗号、RFC 8439 準拠）
- `Disperl::Voice::Ogg` — ffmpeg の libopus 出力（`-f ogg`）から Opus パケットを取り出す demuxer
- `Disperl::Voice::Player` — yt-dlp + ffmpeg（libopus・48kHz・20ms）の音源

追加の CPAN 依存はありません（Perl core + `IO::Socket::SSL` まで）。

## 目次

- [音声への接続](#音声への接続)
- [再生](#再生)
- [E2EE（DAVE）](#e2eedave)
- [音源（Ogg / Player）](#音源ogg--player)
- [モジュール一覧](#モジュール一覧)
- [関連ページ](#関連ページ)

## 音声への接続

`VOICE_STATE_UPDATE` と `VOICE_SERVER_UPDATE`（または `READY` の `voice_states`）から
必要な 5 要素を集めて渡します。

```perl
my $dave  = Disperl::Voice::Dave->new(user_id => $bot_user_id);
$dave->setup_keys;                     # 鍵を生成（保存は呼び出し側で）

my $voice = Disperl::Voice->new(
    token      => $voice_server_update->{token},
    endpoint   => $voice_server_update->{endpoint},
    server_id  => $guild_id,
    user_id    => $bot_user_id,
    session_id => $voice_state_update->{session_id},
    dave       => $dave,               # E2EE（省略すると transport 暗号のみ）
    on_state     => sub { ... },
    on_track_end => sub { ... },
    on_error     => sub { ... },
);

$voice->connect;                       # handshake（ブロッキング）
```

イベントループ側:

```perl
my $timeout = $voice->idle_timeout // 1;
... select を $voice->fh / $voice->udp_fh で $timeout だけ待つ ...
$voice->pump;                          # 受信 / heartbeat / フレーム送信
```

- identify の `max_dave_protocol_version` は `dave` を渡したとき 1、それ以外 0
- `select_protocol` はセッションにつき 1 回（再送すると 4006 で切れる）
- 断線時は呼び出し側で VC 再参加（gateway の op 4）して `VOICE_SERVER_UPDATE` を
  再取得し、同じ `Disperl::Voice` オブジェクトで `connect` し直す

## 再生

`next_frame()`（20ms 1 フレームの Opus バイトを返す。無ければ undef）と
`done`（真で終端）を持つオブジェクトを渡します。

```perl
$voice->play($source);
$voice->pause;     # 5 フレームの無音を送ってから休止
$voice->resume;
$voice->stop_source;   # 5 フレームの無音 + on_track_end('stopped')
```

- 再生が終端すると 5 フレームの無音を送って `on_track_end('finished')` を出す
- フレームは 20ms 間隔で追いつくように送り、最大 10 フレームまで追い回す

## E2EE（DAVE）

DAVE は MLS（[RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)）によるグループ鍵交換と、
AES-128-GCM によるメディアフレーム暗号からなる Discord の E2EE です。
voice gateway が MLS の external sender（交付サービス）として動作します。

```perl
my $dave = Disperl::Voice::Dave->new(user_id => $bot_user_id);
$dave->setup_keys;        # 署名鍵 / HPKE 鍵を生成。seed_file 渡せば保存・再利用

# voice gateway から届いた DAVE メッセージを渡す
$dave->handle_json($msg)     if $msg->{op} == 24;      # prepare_epoch など
$dave->handle_binary($bin);                            # opcode 20-31 のバイナリ

# 出力キューに積まれたものを WS に流す（$voice->pump が内部でやる）
for my $json ($dave->drain_outbound_json) { $ws->send_text($json) }
for my $bin  ($dave->drain_outbound)      { $ws->send_frame(0x2, $bin) }

# メディアフレーム
my $frame = $dave->encrypt_frame($opus);
my $opus  = $dave->decrypt_frame($frame, $sender_user_id);
```

- `Disperl::Voice` に `dave` を渡すと、identify で `max_dave_protocol_version: 1` を出し、
  `select_protocol_ack` の `dave_protocol_version` が 1 以上のとき
  送信フレームを DAVE で包んでから transport 暗号をかける（無音フレームは平文で通過）
- メディアフレーム形式: `ciphertext || tag(8) || ULEB128(nonce) || ULEB128 ranges || size || 0xFAFA`
- 鍵ラチェットの基底秘密は `MLS-Exporter("Discord Secure Frames v0", LE64(userID), 16)`
- 世代は nonce の最上位バイト（2^24 フレームごとにラチェット、epoch 交代で nonce リセット）
- 鍵の保存先（`seed_file`）は呼び出し側で決める（bot として同じ identity を使い続けるため）

### MLS の実装範囲

ciphersuite 2（P-256 + AES-128-GCM + SHA-256）のみ。basic credential、
Add / Remove proposal、Welcome、Commit、ratchet_tree 拡張の復号に対応する。
純 Perl（依存モジュールなし）で P-256 の ECDH / ECDSA を実装しています。

## 音源（Ogg / Player）

20ms フレーム単位で音源を流す 2 枚の部品です。

```perl
my $player = Disperl::Voice::Player->new(url => 'https://example.com/song.mp3');
$player->start;
$voice->play($player);     # Player は next_frame / done を実装している
```

Player は http(s) の直リンクとローカルファイルを受け取り、バックエンドを
2 つ持つ（`backend` で指定、既定は `auto` = 拡張子で判定）:

| バックエンド | 対象 | ffmpeg | 音量 |
|---|---|---|---|
| `passthrough` | ogg/opus（48kHz・20ms・960 サンプル） | 不要 | 不可 |
| `ffmpeg` | その他のフォーマット | 必要 | 可 |

- `passthrough` は OpusHead とフレーム長を検査し、20ms 以外（60ms など）や
  ogg でないストリームはエラーになる。音量変更（`volume != 1.0`）も不可
- ffmpeg は外部ツール（CPAN 依存ではない）。URL の解決（検索語 /
  プレイリスト等）は呼び出し側の責務
- ffmpeg がない環境では passthrough の ogg/opus 音源を使うか、
  `next_frame` / `done` を実装した任意のオブジェクトを `play` に直接渡す

`Disperl::Voice::Ogg` は ogg ページの demuxer だけ（OpusHead / OpusTags はスキップ、
ページまたぎの lacing 255 パケットにも対応）:

```perl
my $demux = Disperl::Voice::Ogg->new;
my @opus_packets = $demux->feed($ogg_bytes);
```

## モジュール一覧

| モジュール | 役割 |
|---|---|
| `Disperl::Voice` | voice gateway v8 接続・RTP 送信・再生制御（play / pause / resume / stop） |
| `Disperl::Voice::Dave` | DAVE（E2EE）。MLS 鍵交換 + メディアフレーム暗号化 |
| `Disperl::Voice::Dave::MLS` | MLS 1.0（RFC 9420）のシリアライザ・署名（ciphersuite 2） |
| `Disperl::Voice::Dave::MLSState` | グループ状態。Welcome / Commit の処理・exporter 導出 |
| `Disperl::Voice::Dave::MLSTree` | array-based ratchet tree の index 計算と tree_hash |
| `Disperl::Voice::Dave::KeySchedule` | RFC 9420 §8 のキースケジュール + DAVE メディアキー導出 |
| `Disperl::Voice::Dave::P256` | 依存なしの P-256（Montgomery CIOS）ECDH / ECDSA |
| `Disperl::Voice::Dave::AesGcm` | 依存なしの AES-128-GCM（タグ 8/16 バイト） |
| `Disperl::Voice::Dave::Hpke` | HPKE（RFC 9180）base mode（DHKEM(P-256) / HKDF-SHA256 / AES-128-GCM） |
| `Disperl::Voice::Dave::Hkdf` | HKDF-SHA256 / ExpandWithLabel / MLS-Exporter |
| `Disperl::Voice::Dave::TLS` | RFC 9420 の TLS presentation language（可変長 `<V>` 付き） |
| `Disperl::Voice::Crypto` | XChaCha20-Poly1305（transport 暗号） |
| `Disperl::Voice::Ogg` | ogg ページ demuxer（`feed` → Opus パケット列） |
| `Disperl::Voice::Player` | 音源（ogg/opus パススルー = ffmpeg 不要 / ffmpeg リエンコード） |

## 関連ページ

- [ステージインスタンス](stage.md)
- [Gateway](gateway.md)
- [チュートリアル](tutorial.md)
