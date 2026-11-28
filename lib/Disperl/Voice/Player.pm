package Disperl::Voice::Player;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Time::HiRes qw(time);
use Errno qw(EAGAIN EWOULDBLOCK);
use Disperl::Voice::Ogg;

# 1 曲分の Opus フレームを供給する音源。
#
#   my $track = Disperl::Voice::Player->new(url => 'https://...');
#   $track->start;                       # 取得 + 起動（ブロッキング）
#   my $frame = $track->next_frame;      # opus パケット。無ければ undef
#   $track->done                         # 終端に達したら真
#   $track->stop;                        # 処理を止める
#
# バックエンド:
#   passthrough - ogg/opus の直リンク・ローカルファイル。OpusHead が
#                 48kHz / 20ms（960 サンプル）ならそのままフレームを送る
#                 （ffmpeg 不要）。音量変更不可。
#   ffmpeg      - 任意のフォーマットを ffmpeg（libopus）で 48kHz・20ms に
#                 エンコード（要 ffmpeg）。音量変更可。
#
# backend => auto（既定）は url の拡張子から ogg/opus なら passthrough、
# それ以外は ffmpeg を選ぶ。拡張子が判断できない URL では ffmpeg を使う。
#
# 受け付ける url: http/https の直リンクかローカルファイル。
# 検索語 / プレイリストの解決は呼び出し側の責務（メタデータは
# title / duration で渡すのがよいが省略可）。
# ライブ配信（ストリーム）は未対応。

my %OEXT = map { $_ => 1 } qw(ogg opus);
my $FRAME_SAMPLES_20MS = 960;    # 48kHz の 20ms

sub new {
    my ($class, %args) = @_;

    die "url is required\n" unless defined $args{url} && length $args{url};
    my $url = $args{url};
    die "url must be http(s) or an existing file: $url\n"
        unless $url =~ m{^[a-z][a-z0-9+.-]*://} || -e $url;

    my $volume = exists $args{volume} ? $args{volume} + 0 : 1.0;
    $volume = 0   if $volume < 0;
    $volume = 2.0 if $volume > 2.0;

    my $force_passthrough = delete $args{force_passthrough} // 0;

    my $backend = lc($args{backend} // 'auto');
    die "unknown backend: $backend\n"
        unless $backend eq 'auto' || $backend eq 'passthrough' || $backend eq 'ffmpeg';

    if ($backend eq 'auto') {
        $backend = _choose_backend($url, $force_passthrough);
    }

    if ($backend eq 'passthrough' && $volume != 1.0) {
        die "passthrough（ogg/opus）では音量変更できません（volume は 1.0 で）\n";
    }

    return bless {
        url      => $url,
        backend  => $backend,
        seek     => ($args{seek} // 0) + 0,          # 再開位置（秒）。ffmpeg 時のみ有効
        volume   => $volume,
        ffmpeg   => $args{ffmpeg} || $ENV{FFMPEG_PATH} || 'ffmpeg',
        timeout  => $args{timeout} // 20,

        title    => $args{title},
        duration => $args{duration},

        fh       => undef,
        pid      => undef,
        is_file  => $backend eq 'passthrough' && _is_local($url),
        local_fh => undef,
        ogg      => Disperl::Voice::Ogg->new(capture_head => 1),
        frames   => [],
        verified => 0,
        done     => 0,
    }, $class;
}

sub _is_local      { $_[0] !~ m{^[a-z][a-z0-9+.-]*://} }
sub _looks_like_ogg_opus { my ($url) = @_; my ($ext) = $url =~ m{\.([a-z0-9]+)(?:[?#].*)?$}i; return $ext && $OEXT{$ext} }

# バックエンドを自動選択する。
#   force_passthrough => 1 : ユーザーが "中身は Opus だと保証" する場合、
#                            拡張子に関わらず passthrough を試す
#   拡張子が .ogg / .opus : passthrough
#   ローカルファイルの先頭が OggS + OpusHead : passthrough（拡張子不問）
#   それ以外 : ffmpeg
sub _choose_backend {
    my ($url, $force) = @_;

    return 'passthrough' if $force;
    return 'passthrough' if _looks_like_ogg_opus($url);
    return 'passthrough' if _is_ogg_opus_by_header($url);

    return 'ffmpeg';
}

# ローカルファイルの先頭を peek して Ogg Opus か判定する。
# OpusHead（RFC 7845 §4.1）が見つかれば "Ogg にラップされた Opus" と確定。
sub _is_ogg_opus_by_header {
    my ($url) = @_;

    return 0 if $url =~ m{^[a-z][a-z0-9+.-]*://};    # HTTP は先頭 peek しない
    return 0 unless -e $url;

    my $fh;
    return 0 unless open($fh, '<:raw', $url);
    my $buf = '';
    my $n = sysread($fh, $buf, 4096);
    close $fh;
    return 0 unless defined $n && $n > 0;
    return 0 unless substr($buf, 0, 4) eq 'OggS';
    return index($buf, 'OpusHead') >= 0 ? 1 : 0;
}

sub title    { $_[0]->{title} }
sub duration { $_[0]->{duration} }
sub url      { $_[0]->{url} }
sub volume   { $_[0]->{volume} }
sub backend  { $_[0]->{backend} }

# 取得を開始する。passthrough ならファイル/URL を開くだけ（OpusHead 検査は
# 最初の読み込みで）。ffmpeg なら ffmpeg を起動する。
sub start {
    my ($self) = @_;

    if ($self->{backend} eq 'passthrough') {
        return $self->_open_passthrough;
    }

    my $is_url = $self->{url} =~ m{^[a-z][a-z0-9+.-]*://};
    warn "[player] ffmpeg path: [$self->{ffmpeg}]\n";
    my @cmd = (
        $self->{ffmpeg},
        qw(-hide_banner -loglevel error -nostdin),
        # reconnect はネットワーク入力専用（ローカルファイルではエラーになる）
        ($is_url ? (qw(-reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 10)) : ()),
        ($self->{seek} > 0 ? ('-ss', $self->{seek}) : ()),
        '-i', $self->{url},
        qw(-vn -ac 2 -ar 48000 -map_metadata -1),
        ($self->{volume} != 1.0 ? ('-filter:a', 'volume=' . $self->{volume}) : ()),
        qw(-c:a libopus -b:a 128k -frame_duration 20 -f ogg pipe:1),
    );

    my $pid = open(my $fh, '-|', @cmd)
        or die "ffmpeg の起動に失敗: $!\n";
    binmode $fh;
    $fh->blocking(0);

    $self->{fh}  = $fh;
    $self->{pid} = $pid;
    return 1;
}

# passthrough: ローカルファイル / http(s) を開いて ogg バイト列を受け取る。
sub _open_passthrough {
    my ($self) = @_;

    if ($self->{is_file}) {
        my $fh;
        open($fh, '<:raw', $self->{url})
            or die "ファイルを開けませんでした: $self->{url}: $!\n";
        $fh->blocking(0);
        $self->{fh}     = $fh;
        $self->{local_fh} = $fh;
        return 1;
    }

    require IO::Socket::SSL;
    my ($scheme, $hostport, $path) = $self->{url} =~ m{^([a-z][a-z0-9+.-]*)://([^/]+)(/.*)$};
    die "url が解釈できませんでした: $self->{url}\n" unless defined $hostport;
    $path = '/' unless defined $path;
    my ($host, $port);
    if ($hostport =~ m{^\[(.+)]:(\d+)$}) {
        ($host, $port) = ($1, $2);                    # IPv6 [::1]:8080
    } elsif ($hostport =~ /^(.+):(\d+)$/) {
        ($host, $port) = ($1, $2);
    } else {
        ($host, $port) = ($hostport, $scheme eq 'https' ? 443 : 80);
    }
    my $fh = IO::Socket::SSL->new(
        PeerAddr   => $host,
        PeerPort   => $port,
        Timeout    => $self->{timeout},
        SSL_startHandshake => $scheme eq 'https' ? 1 : 0,
    ) or die "接続に失敗: $self->{url}: $!\n";
    $fh->blocking(0);

    my $req = "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: disperl-voice\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    $fh->syswrite($req);
    $self->{fh}  = $fh;
    $self->{http} = 1;    # 応答ヘッダを先に切り取る
    return 1;
}

sub fh { $_[0]->{fh} }
sub done { $_[0]->{done} ? 1 : 0 }

sub stop {
    my ($self) = @_;

    if (my $pid = delete $self->{pid}) {
        kill 'KILL', $pid;
        waitpid $pid, 1;
    }
    if (my $fh = delete $self->{fh}) {
        eval { close $fh };
    }
    eval { close $self->{local_fh} } if delete $self->{local_fh};
    $self->{done} = 1;
    return 1;
}

sub DESTROY { $_[0]->stop }

# 次の opus フレームを返す。準備ができていなければ undef。
# 終端に達したら done が真になる。
sub next_frame {
    my ($self) = @_;

    return undef if $self->{done};

    if (@{ $self->{frames} }) {
        my $f = shift(@{ $self->{frames} });
        warn "[player] next_frame: cached frame " . length($f) . " bytes\n";
        return $f;
    }

    # ソースから読む（ノンブロッキング。短時間だけ粘る）
    my $deadline = time + 0.05;
    my $err;
    my $read_bytes = 0;
    while (time < $deadline) {
        my $n = sysread($self->{fh}, my $chunk, 65536);
        if (!defined $n) {
            last if $! == EAGAIN || $! == EWOULDBLOCK;
            $err = $!;
            last;
        }
        last if $n == 0;
        $read_bytes += $n;
        $self->_ingest($chunk);
        last if @{ $self->{frames} };
        last if $self->{done};
    }
    warn "[player] next_frame: read ${read_bytes} bytes, frames=" . scalar(@{ $self->{frames} }) . "\n" if $read_bytes > 0 || @{ $self->{frames} } > 0;

    if ($err) {
        $self->{done} = 1;
        die "読み込みエラー: $err\n";
    }

    return shift @{ $self->{frames} };
}

sub _ingest {
    my ($self, $chunk) = @_;

    warn "[player] _ingest: " . length($chunk) . " bytes from source\n";

    if ($self->{backend} eq 'passthrough') {
        $chunk = $self->_strip_http_header($chunk) if $self->{http} && !$self->{verified};
        # 最初のデータは OggS で始まる（それ以外は ogg/opus ではない）。
        if (!$self->{synced} && length $chunk) {
            die "ogg/opus ストリームではありません（OggS 同期なし）: $self->{url}\n"
                unless substr($chunk, 0, 4) eq 'OggS';
            $self->{synced} = 1;
        }
        push @{ $self->{frames} }, $self->{ogg}->feed($chunk);
        # フレーム長が確定するまで検証を続ける（初期ページではまだ不定）。
        my $ok = eval { $self->verify_frame_size; 1 };
        unless ($ok) {
            warn "[player] verify_frame_size failed: $@\n";
        }
        $self->{verified} = 1;
        return;
    }

    # ffmpeg: ogg の demux だけ
    push @{ $self->{frames} }, $self->{ogg}->feed($chunk);
    warn "[player] _ingest: frames=" . scalar(@{ $self->{frames} }) . " after demux\n";
}

# passthrough の http 応答ヘッダを切り取る（ヘッダ内の \r\n\r\n まで）。
# すでにヘッダが終わった chunk が来た場合はそのまま返す。
sub _strip_http_header {
    my ($self, $chunk) = @_;

    return $chunk if $self->{http_done};
    $self->{http_buf} = '' unless defined $self->{http_buf};
    $self->{http_buf} .= $chunk;
    my $pos = index($self->{http_buf}, "\r\n\r\n");
    if ($pos < 0) {
        return '';    # まだヘッダ途中
    }
    $self->{http_buf} = substr($self->{http_buf}, $pos + 4);
    $self->{http_done} = 1;
    return $self->{http_buf};
}

# OpusHead とフレーム長を 20ms / 48kHz であることを確認する（passthrough）。
sub verify_frame_size {
    my ($self) = @_;

    my $head = $self->{ogg}->head;
    die "OpusHead が見つかりません（ogg/opus ファイルでしょうか）: $self->{url}\n"
        unless $head;
    die "OpusHead のサンプルレートは 48kHz である必要があります（現在 " . $head->{input_sample_rate} . "）\n"
        if $head->{input_sample_rate} && $head->{input_sample_rate} != 48000;

    my $samples = $self->{ogg}->frame_samples;
    return 1 if !defined $samples;    # まだ granule 情報が来ない（最初のフレームだけ）

    die "20ms（960 サンプル）のフレームではありません（" . $samples . " サンプル）。"
      . "再エンコードには backend => 'ffmpeg' を使ってください\n"
        unless $samples == $FRAME_SAMPLES_20MS;

    return 1;
}

1;

__END__

=head1 NAME

Disperl::Voice::Player - 音源（ogg/opus パススルー / ffmpeg リエンコード）

=head1 SYNOPSIS

    use Disperl::Voice::Player;

    # ogg/opus（48kHz・20ms）なら ffmpeg 不要
    my $track = Disperl::Voice::Player->new(url => 'https://example.com/song.ogg');

    # それ以外のフォーマットは ffmpeg（libopus）で 48kHz・20ms にエンコード
    my $track2 = Disperl::Voice::Player->new(url => 'https://example.com/song.mp3',
                                             volume => 0.8);

    $track->start;
    my $frame = $track->next_frame;    # opus フレーム
    $track->stop;

=head1 DESCRIPTION

48kHz の Opus フレームを供給する。バックエンドは 2 種類:

=over 4

=item passthrough

ogg/opus の直リンク・ローカルファイル。OpusHead とフレーム長が 48kHz・
20ms（960 サンプル）ならそのままフレームを送る。ffmpeg 不要。
音量変更はできません（volume は 1.0 で）。

=item ffmpeg

任意のフォーマットを ffmpeg（libopus）で 48kHz ステレオ 20ms にエンコード。
音量は ffmpeg の volume フィルタ。音量変更時は seek を付けて再起動する。

=back

C<backend => 'auto'>（既定）は url の拡張子から ogg/opus を passthrough、
それ以外は ffmpeg を選びます。

URL の解決（検索語 / プレイリスト / 短縮リンク等）は呼び出し側の責務です。
ffmpeg は外部ツールであり CPAN 依存ではありません。ffmpeg が無い環境では
passthrough の ogg/opus 音源か、C<next_frame> / C<done> を実装した任意の
オブジェクトを C<play> に直接渡してください。

=cut
