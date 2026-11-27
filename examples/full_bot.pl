#!/usr/bin/perl
# 多機能 Bot の見本（実機テスト用）。
#   perl examples/full_bot.pl
#
# スラッシュコマンド / prefix コマンド / 統計 / タイマー / イベントを
# 1 ファイルにまとめた例です。そのまま動かして disperl の実機テストに使えます。
#
# 必要な .env:
#   DISCORD_TOKEN=...                （必須）
#
# Developer Portal で有効にする Privileged Intent:
#   - MESSAGE_CONTENT（prefix コマンドで本文を読むため）
#   - GUILD_MEMBERS（メンバー追加イベントのため）
#
# Ctrl+C で終了します（統計は終了前にフラッシュされます）。
use strict;
use warnings;
use utf8;
use FindBin;
use lib "$FindBin::Bin/../lib";
use POSIX qw(strftime);
use JSON::PP ();
use Disperl::Config qw(load_dotenv);
use Disperl::Client;
use Disperl::Commands qw(command option);
use Disperl::Components qw(action_row button);
use Disperl::Gateway;
use Disperl::Router;

load_dotenv("$FindBin::Bin/../.env");

die "DISCORD_TOKEN がありません（.env を確認してください）\n"
    unless defined $ENV{DISCORD_TOKEN} && length $ENV{DISCORD_TOKEN};

binmode STDOUT, ':encoding(cp932)';   # 日本語コンソール向け。絵文字を出すなら chcp 65001 + UTF-8
binmode STDERR, ':encoding(cp932)';

my $client = Disperl::Client->new(token => $ENV{DISCORD_TOKEN});
my $STATS_FILE = "$FindBin::Bin/bot_stats.json";

# ================================================================ 統計（JSON 永続化）

my $JSON  = JSON::PP->new->utf8(1)->canonical(1);
my %stats;            # "guild\tchannel\tuser\tdate" => { msg => n, vc => 秒 }
my $stats_dirty = 0;

sub today { strftime '%Y-%m-%d', localtime }

sub load_stats {
    return unless -f $STATS_FILE;
    open my $fh, '<:utf8', $STATS_FILE or do { warn "stats 読み込み失敗: $!\n"; return };
    local $/;
    my $text = <$fh>;
    close $fh;
    my $data = eval { $JSON->decode($text) };
    %stats = %{ $data || {} };
}

sub flush_stats {
    return unless $stats_dirty;
    open my $fh, '>:utf8', $STATS_FILE or do { warn "stats 書き込み失敗: $!\n"; return };
    print {$fh} $JSON->encode(\%stats);
    close $fh;
    $stats_dirty = 0;
}

sub add_message_count {
    my ($guild_id, $channel_id, $user_id) = @_;
    my $key = join "\t", $guild_id, $channel_id, $user_id, today();
    $stats{$key}{msg}++;
    $stats_dirty = 1;
}

sub add_voice_time {
    my ($guild_id, $user_id, $seconds) = @_;
    my $key = join "\t", $guild_id, 'voice', $user_id, today();
    $stats{$key}{vc} += $seconds;
    $stats_dirty = 1;
}

# ================================================================ アプリ ID / ギルド

my $me     = $client->get_current_user
    or die "トークンが無効のようです（get_current_user 失敗）\n";
my $app_id = $ENV{DISCORD_APPLICATION_ID} // $me->{id};

my %system_channel;    # guild_id => system_channel_id のキャッシュ
sub system_channel_of {
    my ($guild_id) = @_;
    return $system_channel{$guild_id} if $system_channel{$guild_id};
    my $guild = $client->get_guild($guild_id) or return undef;
    return $system_channel{$guild_id} = $guild->{system_channel_id};
}

# ================================================================ スラッシュコマンド定義 + 同期

my @commands = (
    command(name => 'ping', description => '応答速度と稼働時間を表示します'),
    command(
        name        => 'dice',
        description => 'ダイスを振ります',
        options     => [
            option(name => 'sides', description => '面の数（既定 6）',  type => 'integer'),
            option(name => 'count', description => '個数（既定 1）',    type => 'integer'),
        ],
    ),
    command(name => 'stat', description => '今日のアクティビティ統計を表示します'),
    command(
        name        => 'pray',
        description => 'ネル司祭長に祈りを捧げます',
    ),
);

my $router = Disperl::Router->new(
    client   => $client,
    on_error => sub {
        my ($message, $ctx) = @_;
        warn "router: $message\n";
    },
);

$router->command(ping => sub {
    my ($ctx) = @_;
    my $uptime = time - $^T;
    $ctx->reply(sprintf 'pong!（稼働 %d 分）', int($uptime / 60));
});

$router->command(dice => sub {
    my ($ctx) = @_;
    my $sides = $ctx->option('sides') // 6;
    my $count = $ctx->option('count') // 1;
    $ctx->reply('🎲 ' . join(', ', map { int(rand($sides)) + 1 } 1 .. $count));
});

$router->command(stat => sub {
    my ($ctx) = @_;
    $ctx->defer;    # 集計に時間がかかるかもしれないので先に受領だけ返す

    my $today = today();
    my (%total, %by_user);
    for my $key (keys %stats) {
        my ($g, $c, $u, $date) = split /\t/, $key;
        next unless ($date // '') eq $today;
        $total{msg} += $stats{$key}{msg} // 0;
        $total{vc}  += $stats{$key}{vc}  // 0;
        $by_user{$u} += $stats{$key}{msg} // 0;
    }
    my @top = (sort { $by_user{$b} <=> $by_user{$a} } keys %by_user)[0 .. 4];
    my $ranking = join "\n", map {
        sprintf '%d. <@%s>: %d 件', $_ + 1, $top[$_], $by_user{ $top[$_] };
    } grep { $by_user{ $top[$_] } } 0 .. $#top;

    $ctx->edit_original(sprintf
        "📊 今日のアクティビティ\nメッセージ: %d 件\nVC 滞在: %d 分\n%s",
        $total{msg}, int(($total{vc} // 0) / 60),
        $ranking || '（データなし）');
});

$router->command(pray => sub {
    my ($ctx) = @_;
    $ctx->reply('🙏 祈りを受け取ってください。良き一日を。');
}, cooldown => 10);

# ================================================================ prefix コマンド

sub send_help {
    my ($channel_id) = @_;
    $client->send_message($channel_id, undef, {
        embeds => [ {
            title       => 'ネル bot コマンド一覧',
            description => "スラッシュコマンド: /ping /dice /stat /pray\n"
                         . "prefix: !help !mystat !ping",
            color       => 0x5865F2,
        } ],
        components => [
            action_row(
                button(style => 'primary', label => '今日の統計', custom_id => 'help:stat'),
            ),
        ],
    });
}

# ================================================================ 統計コマンド

sub reply_my_stat {
    my ($channel_id, $user_id) = @_;
    my $today = today();
    my ($today_n, $total_n, $total_vc) = (0, 0, 0);
    for my $key (keys %stats) {
        my ($g, $c, $u, $date) = split /\t/, $key;
        next unless $u eq $user_id;
        $total_n   += $stats{$key}{msg} // 0;
        $total_vc  += $stats{$key}{vc}  // 0;
        $today_n   += ($stats{$key}{msg} // 0) if $date eq $today;
    }
    $client->send_message($channel_id,
        sprintf "あなたの統計\n今日: %d 件 / 合計: %d 件 / VC: %.1f 時間",
        $today_n, $total_n, $total_vc / 3600);
}

# ================================================================ Gateway

my %voice_tracker;    # user_id => { guild_id, since }

my $gw;
$gw = Disperl::Gateway->new(
    token   => $ENV{DISCORD_TOKEN},
    intents => [qw(GUILDS GUILD_MEMBERS GUILD_MESSAGES GUILD_VOICE_STATES MESSAGE_CONTENT)],
    on_ready => sub {
        my $user = $gw->user;
        print "ログインしました: $user->{username}（Ctrl+C で終了）\n";

        # ---- タイマー（run ループに乗る） ----
        $gw->every(300 => \&flush_stats, name => 'stats_flush');
        $gw->rotate_presence(
            messages => ['祈祷中', '/stat で統計確認', 'disperl 製'],
            interval => 30,
            status   => 'idle',
        );
    },
    on_message => sub {
        my ($msg) = @_;
        return if $msg->{author}{bot};

        # 発言カウント（ギルド内のみ）
        add_message_count($msg->{guild_id}, $msg->{channel_id}, $msg->{author}{id})
            if $msg->{guild_id};

        my $content = $msg->{content} // '';
        if ($content eq '!ping') {
            $client->send_message($msg->{channel_id}, 'pong!');
        } elsif ($content eq '!help') {
            send_help($msg->{channel_id});
        } elsif ($content eq '!mystat') {
            reply_my_stat($msg->{channel_id}, $msg->{author}{id});
        }
    },
    on_guild_member_add => sub {
        my ($member) = @_;
        my $user    = $member->{user} // {};
        my $guild_id = $member->{guild_id};
        my $ch = system_channel_of($guild_id) or return;
        $client->send_message($ch,
            "🙏 ようこそ <@{$user->{id}}>。司祭長ネルがお迎えします。");
    },
    on_guild_member_update => sub {
        my ($member) = @_;
        # premium_since がペイロードに含まれるのはブースト開始 / 解除のタイミング
        return unless exists $member->{premium_since};
        return unless defined $member->{premium_since};    # undef は解除

        my $guild_id = $member->{guild_id};
        my $ch = system_channel_of($guild_id) or return;
        $client->send_message($ch,
            "🙏 <@{$member->{user}{id}}> がサーバーをブーストしました。祝福を!");
    },
    on_voice_state_update => sub {
        my ($vs) = @_;
        return if $vs->{member}{user}{bot};
        my $user_id  = $vs->{user_id};
        my $now      = time;

        if (defined $vs->{channel_id}) {
            # 参加 / チャンネル移動: 前のセッションがあれば精算して付け直す
            if (my $old = $voice_tracker{$user_id}) {
                add_voice_time($old->{guild_id}, $user_id, $now - $old->{since});
            }
            $voice_tracker{$user_id} = {
                guild_id => $vs->{guild_id}, since => $now,
            };
        } elsif ($voice_tracker{$user_id}) {
            # 退出
            my $old = delete $voice_tracker{$user_id};
            add_voice_time($old->{guild_id}, $user_id, $now - $old->{since});
        }
    },
    on_error => sub {
        warn "gateway: $_[0]\n";
    },
);

# ================================================================ 起動

load_stats();

my $guild_id = $ENV{DISCORD_GUILD_ID};
if ($guild_id) {
    my $result = $client->sync_commands($app_id, \@commands, guild_id => $guild_id);
    if ($result) {
        printf "スラッシュコマンド同期: 作成 %d / 更新 %d / 削除 %d\n",
            scalar @{ $result->{created} // [] },
            scalar @{ $result->{updated} // [] },
            scalar @{ $result->{deleted} // [] };
    } else {
        warn "スラッシュコマンドの同期に失敗しました（.env に DISCORD_GUILD_ID を確認）\n";
    }
} else {
    warn "DISCORD_GUILD_ID 未設定のためスラッシュコマンドは同期しません（prefix コマンドのみ動作）\n";
}

local $SIG{INT} = sub {
    print "\n終了します（統計をフラッシュ）...\n";
    flush_stats();
    $gw->stop;
};

print "起動完了。Ctrl+C で終了\n";
$gw->run;

flush_stats();    # 念のため最終フラッシュ
print "終了\n";
