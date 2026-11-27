package Disperl::Gateway;
use strict;
use warnings;

our $VERSION = '0.1.0';

use JSON::PP;
use Time::HiRes qw(time);
use Disperl::WebSocket;

my $JSON = JSON::PP->new->utf8(1);

my %INTENTS = (
    GUILDS                    => 1 << 0,
    GUILD_MEMBERS             => 1 << 1,     # privileged
    GUILD_MODERATION          => 1 << 2,
    GUILD_EMOJIS_AND_STICKERS => 1 << 3,
    GUILD_INTEGRATIONS        => 1 << 4,
    GUILD_WEBHOOKS            => 1 << 5,
    GUILD_INVITES             => 1 << 6,
    GUILD_VOICE_STATES        => 1 << 7,
    GUILD_PRESENCES           => 1 << 8,     # privileged
    GUILD_MESSAGES            => 1 << 9,
    GUILD_MESSAGE_REACTIONS   => 1 << 10,
    GUILD_MESSAGE_TYPING      => 1 << 11,
    DIRECT_MESSAGES           => 1 << 12,
    DIRECT_MESSAGE_REACTIONS  => 1 << 13,
    DIRECT_MESSAGE_TYPING     => 1 << 14,
    MESSAGE_CONTENT           => 1 << 15,    # privileged
    GUILD_SCHEDULED_EVENTS    => 1 << 16,
);

my %STATUS = map { $_ => 1 } qw(online idle dnd invisible offline);

# アクティビティの種類（Discord の activity type）
my %ACTIVITY_TYPE = (
    playing   => 0,
    streaming => 1,
    listening => 2,
    watching  => 3,
    custom    => 4,
    competing => 5,
);

# Gateway の capabilities（intents とは別のビットフィールド）。
my %CAPABILITY = (
    CHANNEL_OBFUSCATION => 1 << 15,
);

# 既定は GUILDS | GUILD_MESSAGES。本文まで読むには MESSAGE_CONTENT を足す
# （Discord の Developer Portal で Privileged Intent を有効にする必要がある）。
my $DEFAULT_INTENTS = $INTENTS{GUILDS} | $INTENTS{GUILD_MESSAGES};

# 型付きコールバック（Gateway イベント名 => コンストラクタの引数名）。
# 引数は ($data, $msg) で呼ばれる。INTERACTION_CREATE は種別ごとの
# on_command などがあるため、ここには含めない。
my %TYPED_CALLBACK = (
    MESSAGE_CREATE                => 'on_message',
    MESSAGE_UPDATE                => 'on_message_update',
    MESSAGE_DELETE                => 'on_message_delete',
    MESSAGE_DELETE_BULK           => 'on_message_delete_bulk',
    MESSAGE_REACTION_ADD          => 'on_reaction_add',
    MESSAGE_REACTION_REMOVE       => 'on_reaction_remove',
    MESSAGE_REACTION_REMOVE_ALL   => 'on_reaction_remove_all',
    MESSAGE_REACTION_REMOVE_EMOJI => 'on_reaction_remove_emoji',
    MESSAGE_POLL_VOTE_ADD         => 'on_poll_vote_add',
    MESSAGE_POLL_VOTE_REMOVE      => 'on_poll_vote_remove',
    TYPING_START                  => 'on_typing_start',

    GUILD_CREATE         => 'on_guild_create',
    GUILD_UPDATE         => 'on_guild_update',
    GUILD_DELETE         => 'on_guild_delete',
    GUILD_MEMBER_ADD     => 'on_guild_member_add',
    GUILD_MEMBER_UPDATE  => 'on_guild_member_update',
    GUILD_MEMBER_REMOVE  => 'on_guild_member_remove',
    GUILD_MEMBERS_CHUNK  => 'on_guild_members_chunk',
    GUILD_BAN_ADD        => 'on_guild_ban_add',
    GUILD_BAN_REMOVE     => 'on_guild_ban_remove',
    GUILD_ROLE_CREATE    => 'on_guild_role_create',
    GUILD_ROLE_UPDATE    => 'on_guild_role_update',
    GUILD_ROLE_DELETE    => 'on_guild_role_delete',

    GUILD_EMOJIS_UPDATE      => 'on_guild_emojis_update',
    GUILD_STICKERS_UPDATE    => 'on_guild_stickers_update',
    GUILD_INTEGRATIONS_UPDATE => 'on_guild_integrations_update',
    INTEGRATION_CREATE       => 'on_integration_create',
    INTEGRATION_UPDATE       => 'on_integration_update',
    INTEGRATION_DELETE       => 'on_integration_delete',

    ENTITLEMENT_CREATE => 'on_entitlement_create',
    ENTITLEMENT_UPDATE => 'on_entitlement_update',
    ENTITLEMENT_DELETE => 'on_entitlement_delete',

    SUBSCRIPTION_CREATE => 'on_subscription_create',
    SUBSCRIPTION_UPDATE => 'on_subscription_update',
    SUBSCRIPTION_DELETE => 'on_subscription_delete',

    CHANNEL_CREATE      => 'on_channel_create',
    CHANNEL_UPDATE      => 'on_channel_update',
    CHANNEL_DELETE      => 'on_channel_delete',
    CHANNEL_INFO        => 'on_channel_info',
    CHANNEL_PINS_UPDATE => 'on_channel_pins_update',

    THREAD_CREATE          => 'on_thread_create',
    THREAD_UPDATE          => 'on_thread_update',
    THREAD_DELETE          => 'on_thread_delete',
    THREAD_LIST_SYNC       => 'on_thread_list_sync',
    THREAD_MEMBER_UPDATE   => 'on_thread_member_update',
    THREAD_MEMBERS_UPDATE  => 'on_thread_members_update',

    INVITE_CREATE => 'on_invite_create',
    INVITE_DELETE => 'on_invite_delete',

    PRESENCE_UPDATE    => 'on_presence_update',
    VOICE_STATE_UPDATE => 'on_voice_state_update',

    VOICE_CHANNEL_STATUS_UPDATE    => 'on_voice_channel_status_update',
    VOICE_CHANNEL_START_TIME_UPDATE => 'on_voice_channel_start_time_update',
    VOICE_CHANNEL_EFFECT_SEND      => 'on_voice_channel_effect_send',

    GUILD_SOUNDBOARD_SOUND_CREATE => 'on_soundboard_sound_create',
    GUILD_SOUNDBOARD_SOUND_UPDATE => 'on_soundboard_sound_update',
    GUILD_SOUNDBOARD_SOUND_DELETE => 'on_soundboard_sound_delete',
    GUILD_SOUNDBOARD_SOUNDS_UPDATE => 'on_soundboard_sounds_update',
    SOUNDBOARD_SOUNDS              => 'on_soundboard_sounds',

    APPLICATION_COMMAND_PERMISSIONS_UPDATE => 'on_command_permissions_update',

    GUILD_SCHEDULED_EVENT_CREATE      => 'on_scheduled_event_create',
    GUILD_SCHEDULED_EVENT_UPDATE      => 'on_scheduled_event_update',
    GUILD_SCHEDULED_EVENT_DELETE      => 'on_scheduled_event_delete',
    GUILD_SCHEDULED_EVENT_USER_ADD    => 'on_scheduled_event_user_add',
    GUILD_SCHEDULED_EVENT_USER_REMOVE => 'on_scheduled_event_user_remove',

    AUTO_MODERATION_ACTION_EXECUTION => 'on_automod_action',
    AUTO_MODERATION_RULE_CREATE      => 'on_automod_rule_create',
    AUTO_MODERATION_RULE_UPDATE      => 'on_automod_rule_update',
    AUTO_MODERATION_RULE_DELETE      => 'on_automod_rule_delete',

    GUILD_AUDIT_LOG_ENTRY_CREATE => 'on_audit_log_entry_create',
);

sub new {
    my ($class, %args) = @_;

    die "Bot token is required\n"
        unless defined $args{token} && length $args{token};

    my $intents = $args{intents};
    if (!defined $intents) {
        $intents = $DEFAULT_INTENTS;
    } elsif (ref $intents eq 'ARRAY') {
        $intents = $class->intent_bits(@$intents);
    }

    # status / activity / activities / afk / since が指定されたら初期プレゼンスを作る
    my $presence;
    if (grep { exists $args{$_} } qw(status activity activities afk since)) {
        $presence = _make_presence(%args);
    }

    # シャード [id, count]。省略時はシャーディングしない。
    my $shard;
    if (defined $args{shard}) {
        my $value = $args{shard};
        die "shard must be an array reference [id, count]\n"
            unless ref $value eq 'ARRAY' && @$value == 2;

        my ($id, $count) = @$value;
        die "shard count must be at least 1\n"
            unless defined $count && !ref $count
                && $count =~ /^\d+\z/ && $count >= 1;
        die "shard id must be between 0 and count - 1\n"
            unless defined $id && !ref $id
                && $id =~ /^\d+\z/ && $id < $count;

        $shard = [ $id + 0, $count + 0 ];
    }

    # capabilities（整数、または名前の配列）。省略時は送らない。
    my $capabilities;
    if (defined $args{capabilities}) {
        my $value = $args{capabilities};
        if (ref $value eq 'ARRAY') {
            $value = $class->capability_bits(@$value);
        }
        die "capabilities must be an integer\n"
            unless defined $value && !ref $value && $value =~ /^\d+\z/;
        $capabilities = $value + 0;
    }

    # プロセス跨ぎ Resume。前回保存した { session_id, seq } を渡すと、
    # 生きているセッションが無い最初の接続で RESUME から始める。
    my $resume_session = $args{resume_session};
    if (defined $resume_session) {
        die "resume_session must be a hash reference with session_id and seq\n"
            unless ref $resume_session eq 'HASH'
                && defined $resume_session->{session_id}
                && length $resume_session->{session_id}
                && defined $resume_session->{seq};
    }

    die "on_session must be a code reference\n"
        if defined $args{on_session} && ref $args{on_session} ne 'CODE';

    # Router を渡すと、インタラクション系のコールバックをまとめて設定できる。
    # 個別の on_* を明示した場合はそちらを優先する。
    if (my $router = $args{router}) {
        die "router must provide callbacks\n"
            unless $router->can('callbacks');

        my %callbacks = $router->callbacks;
        for my $key (sort keys %callbacks) {
            $args{$key} = $callbacks{$key} unless defined $args{$key};
        }
    }

    # 型付きコールバックを引数から拾う（on_message など）
    my %typed;
    {
        my %seen;
        for my $key (values %TYPED_CALLBACK) {
            next if $seen{$key}++;
            $typed{$key} = $args{$key};
        }
    }

    return bless {
        token          => $args{token},
        intents        => $intents,
        url            => $args{url} // 'wss://gateway.discord.gg/?v=10&encoding=json',
        shard          => $shard,
        capabilities   => $capabilities,
        %typed,
        on_event       => $args{on_event},
        on_interaction => $args{on_interaction},
        on_command     => $args{on_command},
        on_component   => $args{on_component},
        on_autocomplete => $args{on_autocomplete},
        on_modal       => $args{on_modal},
        on_ready       => $args{on_ready},
        on_error       => $args{on_error},
        reconnect      => exists $args{reconnect} ? $args{reconnect} : 1,
        max_reconnects => $args{max_reconnects} // 5,
        # 連続で失敗した回数。READY / RESUMED を受けたら 0 に戻す
        failures       => 0,
        # 4008（レート制限）で再接続するまでの待ち時間（秒）
        reconnect_delay => $args{reconnect_delay} // 5,
        # エラー時の再接続待ち（指数バックオフ。error_backoff * 2^(failures-1)、上限 max_backoff）
        error_backoff => $args{error_backoff} // 1,
        max_backoff   => $args{max_backoff} // 30,
        timeout        => $args{timeout} // 60,
        # 受信メッセージの上限（バイト）。未指定なら WebSocket 側の既定（32 MiB）
        max_message_size => $args{max_message_size},
        ws_class       => $args{ws_class} // 'Disperl::WebSocket',
        sleep          => $args{sleep} // sub { sleep $_[0] },

        # プレゼンス（ステータス・アクティビティ）
        presence          => $presence,
        presence_pending  => 0,
        presence_next_at  => 0,
        # Discord はプレゼンス更新を 20 秒に 5 回までに制限している
        presence_interval => $args{presence_interval} // 4,
        # プレゼンス文ローテーター（rotate_presence で設定）
        presence_rotation => undef,
        # タイマー（every / after で登録、run ループが駆動）
        timers     => {},
        timer_seq  => 0,

        seq             => undef,
        session_id      => undef,
        application_id  => undef,
        resume_url      => undef,
        resume_next     => 1,
        resume_session  => $resume_session,
        on_session      => $args{on_session},
        awaiting_ack    => 0,
        heartbeat_interval => undef,
        ready           => 0,
        running         => 0,
        ws              => undef,
        fatal           => 0,
    }, $class;
}

sub intents { $_[0]->{intents} }
sub session_id { $_[0]->{session_id} }
sub seq { $_[0]->{seq} }
sub application_id { $_[0]->{application_id} }
sub user { $_[0]->{user} }
sub is_running { $_[0]->{running} }

# 現在のプレゼンス（正規化済みのハッシュ）。未設定なら undef。
sub presence { $_[0]->{presence} }

# シャード [id, count]。シャーディングしていなければ undef。
sub shard { $_[0]->{shard} }

# Identify に送る capabilities（未設定なら undef）。
sub capabilities { $_[0]->{capabilities} }

# サウンドボードの音源を要求する（op 31）。結果は on_soundboard_sounds で受け取る。
#   $gw->request_soundboard_sounds($guild_id1, $guild_id2);
sub request_soundboard_sounds {
    my ($self, @guild_ids) = @_;

    die "at least one guild id is required\n" unless @guild_ids;
    die "not connected to the gateway\n" unless $self->{ws} && $self->{ready};

    my @ids;
    for my $id (@guild_ids) {
        die "guild id must be a non-empty string\n"
            if ref $id || !defined $id || !length $id;
        push @ids, "$id";
    }

    $self->{ws}->send_text($JSON->encode({ op => 31, d => { guild_ids => \@ids } }));
    return 1;
}

# チャンネルの一時情報（ステータス・ボイス開始時刻）を要求する（op 43）。
# 結果は on_channel_info で受け取る。fields は status / voice_start_time。
#   $gw->request_channel_info($guild_id, 'status', 'voice_start_time');
sub request_channel_info {
    my ($self, $guild_id, @fields) = @_;

    die "guild id is required\n" unless defined $guild_id && length $guild_id;
    die "not connected to the gateway\n" unless $self->{ws} && $self->{ready};

    @fields = ('status') unless @fields;

    my %VALID = (status => 1, voice_start_time => 1);
    for my $field (@fields) {
        die "Unknown channel info field: "
            . (ref $field ? 'reference' : (defined $field ? $field : 'undef'))
            . " (expected status or voice_start_time)\n"
            unless defined $field && !ref $field && $VALID{$field};
    }

    $self->{ws}->send_text($JSON->encode({
        op => 43,
        d  => { guild_id => "$guild_id", fields => [@fields] },
    }));
    return 1;
}

# ギルドメンバーを要求する（op 8）。結果は on_guild_members_chunk で受け取る。
# GUILD_MEMBERS（Privileged Intent）が必要。
#   $gw->request_guild_members($guild_id);                    # 全件（limit 0）
#   $gw->request_guild_members($guild_id, query => 'kama');
#   $gw->request_guild_members($guild_id, limit => 10);
#   $gw->request_guild_members($guild_id, presets => ['online']);
#   $gw->request_guild_members($guild_id, user_ids => [ $id1, $id2 ]);  # 最大 100
sub request_guild_members {
    my ($self, $guild_id, %opts) = @_;

    die "guild id is required\n" unless defined $guild_id && length $guild_id;
    die "not connected to the gateway\n" unless $self->{ws} && $self->{ready};

    my %d = (guild_id => "$guild_id");

    if (defined $opts{query}) {
        die "query must be a string\n" if ref $opts{query};
        $d{query} = $opts{query};
    }

    if (defined $opts{limit}) {
        my $limit = $opts{limit};
        die "limit must be between 0 and 100\n"
            unless !ref $limit && $limit =~ /^\d+\z/ && $limit <= 100;
        $d{limit} = $limit + 0;
    }

    if (defined $opts{user_ids}) {
        my $user_ids = $opts{user_ids};
        die "user_ids must be a non-empty array reference\n"
            unless ref $user_ids eq 'ARRAY' && @$user_ids;
        die "user_ids accepts at most 100 ids\n" if @$user_ids > 100;

        $d{user_ids} = [
            map {
                die "user id must be a non-empty string\n"
                    if ref $_ || !defined $_ || !length $_;
                "$_"
            } @$user_ids
        ];
    }

    if (defined $opts{presets}) {
        my $presets = $opts{presets};
        die "presets must be an array reference\n"
            unless ref $presets eq 'ARRAY';

        my %VALID = (online => 1, offline => 1);
        my @presets;
        for my $preset (@$presets) {
            die "Unknown preset: "
                . (ref $preset ? 'reference' : (defined $preset ? $preset : 'undef'))
                . " (expected online or offline)\n"
                unless defined $preset && !ref $preset
                    && $VALID{ lc $preset };
            push @presets, lc $preset;
        }
        $d{presets} = \@presets;
    }

    $d{nonce} = "$opts{nonce}" if defined $opts{nonce};

    # limit / user_ids を省略した場合は全件取得（limit 0）
    $d{limit} = 0 unless exists $d{limit} || exists $d{user_ids};

    $self->{ws}->send_text($JSON->encode({ op => 8, d => \%d }));
    return 1;
}

# 接続中にステータスやアクティビティを変える。接続前なら次の接続で反映される。
#   $gw->set_presence(status => 'idle');
#   $gw->set_presence(status => 'dnd', activity => '作業中');
#   $gw->set_presence(status => 'invisible');           # オフライン表示
#   $gw->set_presence(activity => { type => 'watching', name => '配信' });
#   $gw->set_presence(activity => []);                  # アクティビティを消す
sub set_presence {
    my ($self, %args) = @_;

    $self->{presence} = _make_presence(%args, base => $self->{presence});
    $self->{presence_pending} = 1;
    $self->_flush_presence;
    return 1;
}

# プレゼンス文を一定間隔で切り替え続ける（ちぇんbot のステータスローテーション再現）。
#   $gw->rotate_presence(messages => ['ﾆｬｰ', '時給5円'], interval => 30);
#   $gw->rotate_presence(
#       messages => ['作業中...'], interval => 60, status => 'idle',
#       type => 'playing',
#   );
# 停止するときは stop_rotate_presence を呼ぶ。
sub rotate_presence {
    my ($self, %opts) = @_;

    my $messages = $opts{messages};
    die "messages must be a non-empty array reference of strings\n"
        unless ref $messages eq 'ARRAY' && @$messages;
    for my $text (@$messages) {
        die "messages must be non-empty strings\n"
            unless defined $text && length $text;
    }

    my $interval = $opts{interval} // 30;
    die "interval must be an integer of 5 seconds or more\n"
        unless !ref $interval && $interval =~ /^\d+\z/ && $interval >= 5;

    my $type = $opts{type} // 'watching';
    my %TYPES = map { $_ => 1 } qw(playing streaming listening watching competing);
    die "type must be one of playing / streaming / listening / watching / competing\n"
        unless $TYPES{$type};

    my $status = $opts{status};
    if (defined $status) {
        my %STATUSES = map { $_ => 1 } qw(online idle dnd invisible);
        die "status must be one of online / idle / dnd / invisible\n"
            unless $STATUSES{$status};
    }

    $self->{presence_rotation} = {
        messages => [ map { "$_" } @$messages ],
        interval => $interval + 0,
        type     => $type,
        status   => $status,
        index    => 0,
        next_at  => 0,    # 次のループで即座に 1 回目を適用する
    };

    return 1;
}

# プレゼンス文のローテーションを停止する。動いていなければ 0 を返す。
sub stop_rotate_presence {
    my ($self) = @_;

    return 0 unless $self->{presence_rotation};
    $self->{presence_rotation} = undef;
    return 1;
}

# 繰り返しタイマーを登録する。run ループに乗るので fork 不要の軽い定期処理向け。
#   $gw->every(300 => \&flush_stats, name => 'stats');   # 5 分ごと（名前付き）
#   $gw->every(30  => sub { ... });                      # 無名
# 同じ name で登録し直すと上書きされる（on_ready での冪等セットアップ向け）。
sub every {
    my ($self, $seconds, $code, %opts) = @_;
    return $self->_add_timer($seconds, $code, \%opts, 0);
}

# 1 回だけ発火するタイマーを登録する。
#   $gw->after(10 => sub { ... });                       # 10 秒後
sub after {
    my ($self, $seconds, $code, %opts) = @_;
    return $self->_add_timer($seconds, $code, \%opts, 1);
}

sub _add_timer {
    my ($self, $seconds, $code, $opts, $once) = @_;

    die "interval must be an integer of 1 second or more\n"
        unless defined $seconds && !ref $seconds
            && $seconds =~ /^\d+\z/ && $seconds >= 1;
    die "code must be a code reference\n"
        unless defined $code && ref $code eq 'CODE';

    my $name = $opts->{name} // '#' . (++$self->{timer_seq});
    die "timer name must be a non-empty string\n"
        unless defined $name && length $name;

    $self->{timers}{$name} = {
        code     => $code,
        interval => $seconds + 0,
        next_at  => time + $seconds,   # 登録直後は発火しない（予測可能なため）
        once     => $once,
    };

    return $self;
}

# 名前付きタイマーを解除する。解除できたら 1、見つからなければ 0。
sub cancel_timer {
    my ($self, $name) = @_;

    die "timer name is required\n"
        unless defined $name && length $name;

    return delete $self->{timers}{$name} ? 1 : 0;
}

# 全てのタイマーを解除する。解除した個数を返す。
sub cancel_all_timers {
    my ($self) = @_;
    my $count = scalar keys %{ $self->{timers} };
    $self->{timers} = {};
    return $count;
}

# 登録済みタイマーの一覧（デバッグ用）。name => { interval, next_at, once }
sub timers {
    my ($self) = @_;
    return { map { $_ => { %{ $self->{timers}{$_} } } } keys %{ $self->{timers} } };
}

# タイマーの駆動部。run のループから毎回呼ばれる。
sub _tick_timers {
    my ($self) = @_;

    return 0 unless $self->{ready} && $self->{ws};

    my $now   = time;
    my $fired = 0;
    for my $name (sort keys %{ $self->{timers} }) {
        my $timer = $self->{timers}{$name} or next;
        next if $now < $timer->{next_at};

        if ($timer->{once}) {
            delete $self->{timers}{$name};
        } else {
            $timer->{next_at} = $now + $timer->{interval};
        }

        # エラーは _dispatch が隔離するので、死んでもループと他のタイマーは生きる
        $self->_dispatch("timer '$name'", $timer->{code}, $self);
        $fired++;
    }

    return $fired;
}

# rotate_presence の駆動部。run のループから一定間隔で呼ばれる。
sub _tick_presence_rotation {
    my ($self) = @_;

    my $rotation = $self->{presence_rotation} or return 0;
    return 0 unless ref $rotation eq 'HASH'
        && ref $rotation->{messages} eq 'ARRAY'
        && @{ $rotation->{messages} };
    return 0 unless $self->{ready} && $self->{ws};
    return 0 if time < $rotation->{next_at};

    my $messages = $rotation->{messages};
    my $text     = $messages->[ $rotation->{index} % @$messages ];
    $rotation->{index}++;
    $rotation->{next_at} = time + $rotation->{interval};

    my %args = ( activity => { type => $rotation->{type}, name => $text } );
    $args{status} = $rotation->{status} if defined $rotation->{status};

    return $self->set_presence(%args);
}

# 名前のリストから intents のビットマスクを作る。
#   Disperl::Gateway->intent_bits(qw(GUILDS GUILD_MESSAGES MESSAGE_CONTENT))
sub intent_bits {
    my ($class, @names) = @_;

    my $bits = 0;
    for my $name (@names) {
        die "Unknown intent: $name\n" unless exists $INTENTS{$name};
        $bits |= $INTENTS{$name};
    }
    return $bits;
}

# 名前のリストから capabilities のビットマスクを作る。
#   Disperl::Gateway->capability_bits('CHANNEL_OBFUSCATION')
sub capability_bits {
    my ($class, @names) = @_;

    my $bits = 0;
    for my $name (@names) {
        die "Unknown capability: $name\n" unless exists $CAPABILITY{$name};
        $bits |= $CAPABILITY{$name};
    }
    return $bits;
}

# ---------------------------------------------------------------- presence

# プレゼンスのハッシュを作る。指定が無い項目は base（現在値）を引き継ぐ。
sub _make_presence {
    my (%args) = @_;

    my $base = $args{base} || {
        status     => 'online',
        activities => [],
        afk        => JSON::PP::false,
        since      => JSON::PP::null,
    };

    my $status = exists $args{status}
        ? _normalize_status($args{status})
        : $base->{status};

    my $activities;
    if (exists $args{activities}) {
        die "activities must be an array reference\n"
            unless ref $args{activities} eq 'ARRAY';
        $activities = [map { _normalize_activity($_) } @{ $args{activities} }];
    } elsif (exists $args{activity}) {
        my $value = $args{activity};
        $activities = defined $value
            ? [map { _normalize_activity($_) } (ref $value eq 'ARRAY' ? @$value : ($value))]
            : [];
    } else {
        $activities = $base->{activities};
    }

    return {
        status     => $status,
        activities => $activities,
        afk        => exists $args{afk}
            ? ($args{afk} ? JSON::PP::true : JSON::PP::false)
            : $base->{afk},
        since      => exists $args{since}
            ? _normalize_since($args{since})
            : $base->{since},
    };
}

sub _normalize_status {
    my ($status) = @_;
    $status = lc $status if defined $status;

    die "Unknown status: " . ($status // 'undef')
        . " (expected online, idle, dnd, invisible or offline)\n"
        unless defined $status && $STATUS{$status};

    return $status;
}

sub _normalize_since {
    my ($since) = @_;
    return JSON::PP::null unless defined $since && $since;
    return int($since);
}

sub _normalize_activity {
    my ($activity) = @_;

    $activity = { name => $activity } unless ref $activity;
    die "activity must be a string or hash reference\n"
        unless ref $activity eq 'HASH';

    my $type;
    if (defined $activity->{type} && $activity->{type} =~ /^\d+$/) {
        $type = $activity->{type} + 0;
        die "Unknown activity type: $type\n" unless $type >= 0 && $type <= 5;
    } else {
        my $name = defined $activity->{type} ? lc $activity->{type} : 'playing';
        die "Unknown activity type: $name\n" unless exists $ACTIVITY_TYPE{$name};
        $type = $ACTIVITY_TYPE{$name};
    }

    my %out = (type => $type);

    if ($type == 4) {    # カスタムステータス
        $out{name}  = $activity->{name} // 'Custom Status';
        $out{state} = $activity->{state} // '';
    } else {
        $out{name} = $activity->{name} // '';
        die "activity name is required\n" unless length $out{name};

        $out{url}     = $activity->{url}     if defined $activity->{url};
        $out{state}   = $activity->{state}   if defined $activity->{state};
        $out{details} = $activity->{details} if defined $activity->{details};

        die "streaming activity requires url\n"
            if $type == 1 && !defined $out{url};
    }

    if (defined $activity->{emoji}) {
        my $emoji = $activity->{emoji};
        die "activity emoji must be a hash reference\n"
            unless ref $emoji eq 'HASH';

        my $name_ok = defined $emoji->{name} && !ref $emoji->{name}
            && length $emoji->{name};
        my $id_ok = defined $emoji->{id} && !ref $emoji->{id}
            && length $emoji->{id};
        die "activity emoji requires a name or id\n"
            unless $name_ok || $id_ok;

        my %out_emoji;
        $out_emoji{name} = $emoji->{name} if $name_ok;
        $out_emoji{id}   = $emoji->{id}   if $id_ok;
        $out_emoji{animated} = $emoji->{animated}
            ? JSON::PP::true : JSON::PP::false
            if exists $emoji->{animated};
        $out{emoji} = \%out_emoji;
    }

    return \%out;
}

# 現在のプレゼンスを送る（op 3）。
sub _apply_presence {
    my ($self) = @_;

    return unless $self->{presence};
    return unless $self->{ws};

    $self->{ws}->send_text($JSON->encode({ op => 3, d => $self->{presence} }));
    $self->{presence_pending} = 0;
    $self->{presence_next_at} = time + $self->{presence_interval};
    return 1;
}

# 予約されたプレゼンス更新を、制限間隔を空けて送る。
sub _flush_presence {
    my ($self) = @_;

    return unless $self->{presence_pending};
    return unless $self->{ready} && $self->{ws};
    return if time < $self->{presence_next_at};

    return $self->_apply_presence;
}

# 接続してイベントを処理し続ける。stop() が呼ばれるか、リトライ上限に達するまで戻らない。
sub run {
    my ($self) = @_;

    $self->{running} = 1;

    while ($self->{running}) {
        my $reason = eval { $self->_run_once };
        if (my $err = $@) {
            $self->_report($err);
            $reason = 'error';
            last if $self->{fatal};
        }

        last unless $self->{running};
        last if defined $reason && $reason eq 'stop';

        # 連続失敗回数。READY / RESUMED で 0 に戻るので、
        # 一度正常につながれば max_reconnects はリセットされる。
        $self->{failures}++ if defined $reason && $reason eq 'error';
        last unless $self->{reconnect};
        last if $self->{failures} > $self->{max_reconnects};

        my $wait = $self->_reconnect_wait($reason);
        $self->{sleep}->($wait) if $wait;
    }

    $self->{running} = 0;
    return 1;
}

# 再接続までの待ち時間（秒）。理由に応じて変える。
#   error           => 指数バックオフ（error_backoff * 2^(failures-1)、上限 max_backoff）
#   rate_limited    => reconnect_delay
#   invalid_session => 1〜5 秒（Discord の推奨）
sub _reconnect_wait {
    my ($self, $reason) = @_;

    return 0 unless defined $reason;

    if ($reason eq 'error') {
        my $failures = $self->{failures} > 0 ? $self->{failures} : 1;
        my $wait = $self->{error_backoff} * (2 ** ($failures - 1));
        $wait = $self->{max_backoff} if $wait > $self->{max_backoff};
        return $wait;
    }

    return $self->{reconnect_delay} if $reason eq 'rate_limited';
    return 1 + rand(4) if $reason eq 'invalid_session';

    # 汎用クローズ / ゾンビ検出。即時再接続を繰り返さないよう最低 1 秒空ける
    return 1 if $reason eq 'resume';

    return 0;
}

sub stop {
    my ($self) = @_;

    $self->{running} = 0;
    if (my $ws = $self->{ws}) {
        eval { $ws->close(1000) };
    }
    return 1;
}

# ---------------------------------------------------------------- internals

sub _run_once {
    my ($self) = @_;
    $self->{running} = 1;

    my $ws = $self->_connect;
    $self->{ws} = $ws;
    $self->{awaiting_ack} = 0;
    $self->{ready} = 0;

    my $frame = $ws->recv_frame(timeout => $self->{timeout});
    die "Timed out waiting for Hello (op 10) from the gateway\n"
        unless $frame;

    if ($frame->{opcode} == 8) {
        my $code = $frame->{code} // '?';
        my $reason = $frame->{reason} // '';
        die "Gateway closed during handshake (code $code"
            . (length $reason ? " $reason" : '') . ")\n";
    }

    my $hello = eval { $JSON->decode($frame->{payload}) };
    die "Invalid Hello (op 10) payload from the gateway\n"
        unless ref $hello eq 'HASH' && ($hello->{op} // -1) == 10;

    my $interval = ($hello->{d}{heartbeat_interval} // 41250) / 1000;
    $self->{heartbeat_interval} = $interval;
    my $next_heartbeat = time + $interval * rand();

    if ($self->{resume_next} && $self->{session_id} && defined $self->{seq}) {
        $self->_resume($ws);
    } elsif ($self->{resume_next} && ref $self->{resume_session} eq 'HASH') {
        # プロセス跨ぎ Resume: 保存されたセッションで再開を試みる。
        # 無効だった場合は op 9 → Identify に落ちる。
        $self->{session_id} = $self->{resume_session}{session_id};
        $self->{seq}        = $self->{resume_session}{seq};
        $self->_resume($ws);
    } else {
        $self->_identify($ws);
    }

    my $reason = 'closed';
    while ($self->{running}) {
        my $now = time;

        # 予約されたプレゼンス更新（レート制限の間隔待ち）を送る
        $self->_flush_presence;
        $self->_tick_presence_rotation;
        $self->_tick_timers;

        if ($now >= $next_heartbeat) {
            if ($self->{awaiting_ack}) {
                # 前回の ACK が返ってこない = ゾンビ接続
                $self->_report("Heartbeat ACK not received; reconnecting\n");
                $reason = 'resume';
                last;
            }
            $self->_heartbeat($ws);
            $self->{awaiting_ack} = 1;
            $next_heartbeat = $now + $interval;
        }

        my $wait = $next_heartbeat - time;

        # プレゼンス更新の待ち時間の方が短ければそちらに合わせる
        if ($self->{presence_pending} && $self->{ready}) {
            my $presence_wait = $self->{presence_next_at} - time;
            $presence_wait = 0 if $presence_wait < 0;
            $wait = $presence_wait if $presence_wait < $wait;
        }

        $wait = 0.05 if $wait < 0.05;
        # stop() / Ctrl+C の応答性を保つため、受信待ちに 1 秒の上限を付ける
        #（Windows はシグナルで select / sysread を中断できないため）
        $wait = 1 if $wait > 1;

        my $frame = $ws->recv_frame(timeout => $wait);
        next unless $frame;

        if ($frame->{opcode} == 8) {
            my $code = $frame->{code};

            # トークン不正・intents 不正などは再接続しても直らない
            if (defined $code && ($code == 4004 || ($code >= 4010 && $code <= 4014))) {
                $self->{fatal} = 1;
                die "Fatal gateway close code $code\n";
            }

            # セッションが無効になった場合は Resume せず Identify からやり直す
            if (defined $code && ($code == 4006 || $code == 4007 || $code == 4009)) {
                $self->_forget_session;
                $reason = 'resume';
                last;
            }

            # 4008 はレート制限。すぐには再接続せず、少し待つ
            if (defined $code && $code == 4008) {
                $reason = 'rate_limited';
                last;
            }

            $reason = 'resume';
            last;
        }

        my $msg = eval { $JSON->decode($frame->{payload}) };
        next unless ref $msg eq 'HASH';

        my $action = $self->_handle($msg);
        if ($action) {
            $reason = $action;
            last;
        }
    }

    $self->{ws} = undef;
    eval { $ws->close(1000) };
    return $reason;
}

# op を処理する。再接続が必要なら理由を返す。
sub _handle {
    my ($self, $msg) = @_;
    my $op = $msg->{op} // -1;

    if ($op == 0) {                         # Dispatch
        $self->{seq} = $msg->{s} if defined $msg->{s};
        $self->_notify_session
            if defined $msg->{s} && defined $self->{session_id};

        my $type = $msg->{t} // '';
        my $data = $msg->{d};

        if ($type eq 'READY') {
            $self->{session_id}  = $data->{session_id};
            $self->{resume_url}  = $data->{resume_gateway_url};
            $self->{user}        = $data->{user};
            $self->{application_id} = $data->{application}{id}
                if ref $data->{application} eq 'HASH';
            $self->{resume_next} = 1;
            $self->{ready}       = 1;
            $self->{failures}    = 0;
            $self->_notify_session;
            # Identify 後に set_presence されていれば、ここで反映する
            $self->_flush_presence;
            $self->_dispatch('on_ready', $self->{on_ready}, $data);
        } elsif ($type eq 'RESUMED') {
            $self->{ready}    = 1;
            $self->{failures} = 0;
            $self->_notify_session;
            $self->{presence_pending} = 1 if $self->{presence};
            $self->_apply_presence;
        } elsif ($type eq 'INTERACTION_CREATE') {
            $self->_dispatch('on_interaction', $self->{on_interaction}, $data);

            # type 2 = スラッシュコマンド、type 3 = ボタン / セレクト、
            # type 4 = オートコンプリート、type 5 = モーダル送信
            my $kind = $data->{type} // 0;
            $self->_dispatch('on_command', $self->{on_command}, $data)
                if $kind == 2;
            $self->_dispatch('on_component', $self->{on_component}, $data)
                if $kind == 3;
            $self->_dispatch('on_autocomplete', $self->{on_autocomplete}, $data)
                if $kind == 4;
            $self->_dispatch('on_modal', $self->{on_modal}, $data)
                if $kind == 5;
        } elsif (my $callback = $TYPED_CALLBACK{$type}) {
            $self->_dispatch($callback, $self->{$callback}, $data, $msg);
        }

        $self->_dispatch('on_event', $self->{on_event}, $type, $data, $msg);
        return undef;
    }

    if ($op == 1) {                         # サーバーからの Heartbeat 要求
        $self->_heartbeat($self->{ws});
        $self->{awaiting_ack} = 1;
        return undef;
    }

    return 'resume' if $op == 7;            # Reconnect

    if ($op == 9) {                         # Invalid Session
        # d が false なら Resume できない。セッションを捨てて Identify からやり直す。
        # d が true の場合は少し待てば Resume できるので、そのまま再開する。
        $self->_forget_session unless $msg->{d};
        return 'invalid_session';
    }

    if ($op == 11) {                        # Heartbeat ACK
        $self->{awaiting_ack} = 0;
        return undef;
    }

    return undef;
}

# セッション保存用の on_session に { session_id, seq } を通知する。
# イベントごとに呼ばれるので、コールバックは軽く保つこと。
sub _notify_session {
    my ($self) = @_;

    my $callback = $self->{on_session} or return undef;
    return undef unless defined $self->{session_id};

    my $ok = eval {
        $callback->({
            session_id => $self->{session_id},
            seq        => $self->{seq},
        });
        1;
    };
    warn "on_session callback failed: $@" unless $ok;
    return 1;
}

# セッションを破棄し、次の接続で必ず Identify からやり直す。
sub _forget_session {
    my ($self) = @_;

    $self->{session_id}  = undef;
    $self->{seq}         = undef;
    $self->{resume_url}  = undef;
    $self->{resume_next} = 0;
}

sub _connect {
    my ($self) = @_;

    my $url = $self->{url};
    if ($self->{resume_next} && $self->{resume_url}) {
        $url = $self->{resume_url};
        if ($url !~ /[?&]v=/) {
            $url .= ($url =~ /\?/ ? '&' : '?') . 'v=10&encoding=json';
        }
    }

    my $class = $self->{ws_class};
    return $class->connect(
        url     => $url,
        timeout => $self->{timeout},
        (defined $self->{max_message_size}
            ? (max_message_size => $self->{max_message_size}) : ()),
    );
}

sub _identify {
    my ($self, $ws) = @_;

    my $d = {
        token   => $self->{token},
        intents => $self->{intents},
        properties => {
            os      => $^O,
            browser => 'disperl',
            device  => 'disperl',
        },
    };
    $d->{presence}     = $self->{presence}     if $self->{presence};
    $d->{shard}        = $self->{shard}        if $self->{shard};
    $d->{capabilities} = $self->{capabilities} if $self->{capabilities};

    $ws->send_text($JSON->encode({ op => 2, d => $d }));

    # Identify に含めた分は送信済みとして扱い、READY での二重送信を避ける
    if ($self->{presence}) {
        $self->{presence_pending} = 0;
        $self->{presence_next_at} = time + $self->{presence_interval};
    }
}

sub _resume {
    my ($self, $ws) = @_;

    $ws->send_text($JSON->encode({
        op => 6,
        d  => {
            token      => $self->{token},
            session_id => $self->{session_id},
            seq        => $self->{seq},
        },
    }));
}

sub _heartbeat {
    my ($self, $ws) = @_;
    $ws->send_text($JSON->encode({ op => 1, d => $self->{seq} }));
}

# コールバックを安全に呼ぶ。die しても接続を切らず on_error に流す。
sub _dispatch {
    my ($self, $label, $callback, @args) = @_;

    return 0 unless $callback;

    my $ok = eval { $callback->(@args); 1 };
    unless ($ok) {
        my $err = $@ || 'unknown error';
        $err =~ s/\s+\z//;
        $self->_report("Error in $label callback: $err");
    }
    return 1;
}

sub _report {
    my ($self, $message) = @_;

    if ($self->{on_error}) {
        # on_error 自体が die しても接続は維持する
        my $ok = eval { $self->{on_error}->($message); 1 };
        warn "on_error callback failed: $@" unless $ok;
        return;
    }
    warn(($message =~ /\n\z/) ? $message : "$message\n");
}

1;
