use strict;
use warnings;
use Test::More;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Disperl::Voice::Ogg;

# ogg ページを組み立てるヘルパー
sub ogg_page {
    my (%args) = @_;
    my $segments = $args{segments};
    my $body = join '', @$segments;
    my @lacing;
    for my $seg (@$segments) {
        # lacing はセグメント長（255 は 0..254 までで打ち切る方式の継続印）
        my $len = length $seg;
        push @lacing, $len;
    }
    my $nseg = scalar @lacing;
    my $header = 'OggS'
        . pack('CC', 0, $args{type} // 0)     # version, header_type
        . pack('Q<', $args{granule} // 0)     # granule
        . pack('N', $args{serial} // 1)       # serial
        . pack('N', $args{seq} // 0)          # page seq
        . pack('N', 0)                        # crc（検証しない）
        . pack('C', $nseg)
        . pack("C$nseg", @lacing);
    return $header . $body;
}

# ---- 基本の取り出し ----
{
    my $demux = Disperl::Voice::Ogg->new;
    my $page = ogg_page(segments => ["OpusHead" . ("\x00" x 11), "OpusTags" . ("\x00" x 4), "\xf8\xff\xfe", "abc"]);
    my @packets = $demux->feed($page);
    is scalar(@packets), 2, 'header packets are skipped';
    is $packets[0], "\xf8\xff\xfe", 'first audio packet';
    is $packets[1], 'abc', 'second audio packet';
}

# ---- ページまたぎ（lacing 255 は手動で構成する必要があるため低レベルで流す） ----
{
    my $demux = Disperl::Voice::Ogg->new;

    # 1 ページ目: 255 バイト + 10 バイトのパケット（lacing [255, 10]）
    my $part1 = 'x' x 255;
    my $part2 = 'y' x 10;
    my $header = 'OggS'
        . pack('CC', 0, 0)
        . pack('Q<', 0)
        . pack('N', 1)
        . pack('N', 0)
        . pack('N', 0)
        . pack('C', 2)
        . pack('C2', 255, 10);
    my @got = $demux->feed($header . $part1);
    is scalar(@got), 0, 'continuing packet is not emitted early';

    @got = $demux->feed($part2);
    is scalar(@got), 1, 'packet completed across feed calls';
    is $got[0], $part1 . $part2, 'spliced packet is the concatenation';
}

# ---- ページまたぎ（複数ページにまたがるパケット） ----
{
    my $demux = Disperl::Voice::Ogg->new;

    # page A: lacing [255] のみ（継続） / page B: lacing [255] / page C: lacing [5]
    my $data = 'z' x (255 + 255 + 5);
    my $page = sub {
        my ($seg_counts) = @_;
        my $header = 'OggS'
            . pack('CC', 0, 0)
            . pack('Q<', 0) . pack('N', 1) . pack('N', 0) . pack('N', 0)
            . pack('C', scalar @$seg_counts)
            . pack('C' . scalar @$seg_counts, @$seg_counts);
        return $header;
    };

    my $buf = $page->([255]) . ('a' x 255)
            . $page->([255]) . ('b' x 255)
            . $page->([5])   . ('c' x 5);
    my @got = $demux->feed($buf);
    is scalar(@got), 1, 'multi-page packet emits once';
    is $got[0], ('a' x 255) . ('b' x 255) . ('c' x 5), 'multi-page packet is complete';
}

# ---- 分割 feed ----
{
    my $demux = Disperl::Voice::Ogg->new;
    my $full = ogg_page(segments => ["\xf8\xff\xfe"]);
    my @got;
    for my $i (0 .. length($full) - 1) {
        push @got, $demux->feed(substr($full, $i, 1));
    }
    is scalar(@got), 1, 'byte-by-byte feed works';
    is $got[0], "\xf8\xff\xfe", 'packet survives byte-by-byte feeding';
}

done_testing();
