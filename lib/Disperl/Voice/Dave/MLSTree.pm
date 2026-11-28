package Disperl::Voice::Dave::MLSTree;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';
use Digest::SHA qw(sha256);

use Disperl::Voice::Dave::TLS qw(tls_u8 tls_u16 tls_u32 tls_u64 tls_opaqueV tls_varint);
use Disperl::Voice::Dave::MLS qw(encode_leaf_node encode_parent_node);

our @EXPORT_OK = qw(
    tree_node_count tree_leaf_count tree_capacity node_level parent_index
    direct_path copath tree_root_hash tree_leaf_hash
);

# RFC 9420 §4 の array-based ratchet tree の index 計算と tree_hash。
#
#   MLS のツリーは常に完全二分木（2^d リーフ）。メンバー数が 2^d でない場合は
#   余りのリーフを blank にして埋める。したがって leaf_count は 2 のべき。
#   葉は偶数 index、親は奇数 index。leaf_count リーフなら 2*leaf_count-1 ノード。
#   ノード i のレベル = i の 2 進表現で末尾に連続する 1 の数。
#   親: 同じリーフ範囲を覆う 1 つ上のノード（左の子なら +2^level、右なら -2^level）。

sub tree_node_count { return $_[0] > 0 ? 2 * $_[0] - 1 : 0 }
sub tree_leaf_count { return $_[0] > 0 ? int(($_[0] + 1) / 2) : 0 }

# n 人を収容する最小の完全二分木のリーフ数（2^ceil(log2(n))、最低 1）
sub tree_capacity {
    my ($n) = @_;
    return 1 if $n <= 1;
    my $cap = 1;
    $cap <<= 1 while $cap < $n;
    return $cap;
}

sub node_level {
    my ($i) = @_;
    my $level = 0;
    $level++ while ($i >> $level) & 1;
    return $level;
}

# 親の index。根なら undef。
sub parent_index {
    my ($i, $node_count) = @_;

    my $level = node_level($i);
    my $step  = 1 << $level;
    my $block = 1 << ($level + 1);
    my $k     = int($i / $block);

    my $parent = ($k % 2 == 0) ? $i + $step : $i - $step;
    return undef if defined $node_count && $parent >= $node_count;
    return $parent;
}

# 葉から根までの direct path（自身を除く）
sub direct_path {
    my ($i, $node_count) = @_;
    my @path;
    my $x = $i;
    while (1) {
        my $p = parent_index($x, $node_count);
        last unless defined $p;
        push @path, $p;
        $x = $p;
    }
    return \@path;
}

# direct path 上の各ノードの兄弟（葉から順）
sub copath {
    my ($i, $node_count) = @_;

    my @copath;
    my $x = $i;
    while (1) {
        my $p = parent_index($x, $node_count);
        last unless defined $p;
        my $level = node_level($p);
        my $step  = 1 << ($level - 1);
        my $sibling = ($x == $p - $step) ? $p + $step : $p - $step;
        push @copath, $sibling if $sibling < $node_count;
        $x = $p;
    }
    return \@copath;
}

# ---------------------------------------------------------------- tree hash

# ツリー全体のハッシュ（RFC 9420 §7.8）
sub tree_root_hash {
    my (%args) = @_;
    my $node_count = $args{node_count};
    my $resolver   = $args{resolver};

    my $root = $node_count - 1;
    # 根は node_count-1 ではない（右端のノードが根）
    $root = _root_index($node_count);
    return _hash_node($root, $node_count, $resolver);
}

# 配列の末尾が根
sub _root_index { return $_[0] - 1 }

sub _hash_node {
    my ($index, $node_count, $resolver) = @_;

    my $node = $resolver->($index);

    if ($index % 2 == 0) {
        # リーフ: TreeHashInput = uint8 leaf(1) || uint32 leaf_index || optional<LeafNode>
        my $leaf = $node ? ($node->{leaf} // $node) : undef;
        my $input = tls_u8(1) . tls_u32($index / 2);
        $input .= $leaf ? (tls_u8(1) . encode_leaf_node($leaf)) : tls_u8(0);
        return sha256($input);
    }

    # 親: TreeHashInput = uint8 parent(2) || optional<ParentNode> || left_hash<V> || right_hash<V>
    my $level = node_level($index);
    my $step  = 1 << ($level - 1);
    my $left  = $index - $step;
    my $right = $index + $step;

    my $parent = $node ? ($node->{parent} // $node) : undef;
    my $input = tls_u8(2);
    if ($parent) {
        # ParentNode = enc_key<V> || parent_hash<V> || uint32 unmerged_leaves<V>
        my $unmerged = $parent->{unmerged_leaves};
        $unmerged = pack('N*', @$unmerged) if ref $unmerged eq 'ARRAY';
        $input .= tls_u8(1)
                . tls_opaqueV($parent->{encryption_key})
                . tls_opaqueV($parent->{parent_hash} // '')
                . tls_opaqueV($unmerged // '');
    } else {
        $input .= tls_u8(0);
    }
    $input .= tls_opaqueV(_hash_node($left,  $node_count, $resolver));
    $input .= tls_opaqueV(_hash_node($right, $node_count, $resolver));
    return sha256($input);
}

sub tree_leaf_hash {
    my ($leaf, $leaf_index) = @_;
    return sha256(tls_u8(1) . tls_u32($leaf_index // 0) . tls_u8(1) . encode_leaf_node($leaf));
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::MLSTree - MLS のラチェットツリー

=head1 DESCRIPTION

array-based ratchet tree の index 計算と tree_hash（RFC 9420 §4, §7.8）。

=cut
