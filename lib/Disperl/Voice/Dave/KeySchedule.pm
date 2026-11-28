package Disperl::Voice::Dave::KeySchedule;
use strict;
use warnings;

our $VERSION = '0.1.0';

use Exporter 'import';
use Digest::SHA qw(sha256 hmac_sha256);

use Disperl::Voice::Dave::Hkdf qw(hkdf_extract hkdf_expand expand_with_label
                                  derive_secret mls_exporter);

our @EXPORT_OK = qw(
    key_schedule_next initial_key_schedule key_schedule_from_joiner
    psk_secret_from_list confirmation_tag send_key
    media_key_base_secret sender_ratchet_key welcome_keys
);

# RFC 9420 §8 のキースケジュール。
#   init_secret[n-1] + commit_secret --Extract--> joiner_secret
#   joiner_secret + psk_secret      --Extract--> epoch_secret
#   epoch_secret --DeriveSecret--> exporter_secret / encryption_secret / ...

my $ZERO32 = "\x00" x 32;

# psk のリスト（PreSharedKeyID + secret）から psk_secret を作る。空なら 0^32。
sub psk_secret_from_list {
    my ($psks) = @_;
    return $ZERO32 unless $psks && @$psks;

    my $count = scalar @$psks;
    my $prev = $ZERO32;
    for my $i (0 .. $count - 1) {
        my $psk = $psks->[$i];
        my $extracted = hkdf_extract($ZERO32, $psk->{secret});
        my $label = (defined $psk->{id} ? $psk->{id} : '')
                  . pack('n', $i) . pack('n', $count);
        my $input = expand_with_label($extracted, 'derived psk', $label, 32);
        $prev = hkdf_extract($input, $prev);
    }
    return $prev;
}

# 次の epoch のキースケジュールを作る。
#   $init_secret  前 epoch の init_secret（最初は 0^32）
#   $commit_secret commit の秘密（パス無しなら 0^32）
#   $psk_secret   psk_secret（無ければ 0^32）
#   $context      GroupContext のシリアライズ
sub key_schedule_next {
    my (%args) = @_;

    my $init_secret   = $args{init_secret}   // $ZERO32;
    my $commit_secret = $args{commit_secret} // $ZERO32;
    my $context       = $args{context}       // '';

    my $pre_joiner    = hkdf_extract($init_secret, $commit_secret);
    my $joiner_secret = expand_with_label($pre_joiner, 'joiner', $context, 32);

    return key_schedule_from_joiner(
        joiner_secret => $joiner_secret,
        psk_secret    => $args{psk_secret},
        context       => $context,
        confirmed_transcript_hash => $args{confirmed_transcript_hash},
    );
}

# joiner_secret が既にある場合（Welcome で参加する側）。
sub key_schedule_from_joiner {
    my (%args) = @_;

    my $joiner_secret = $args{joiner_secret} // $ZERO32;
    my $psk_secret    = $args{psk_secret}    // $ZERO32;
    my $context       = $args{context}       // '';

    my $member_secret = hkdf_extract($joiner_secret, $psk_secret);
    my $epoch_secret  = expand_with_label($member_secret, 'epoch', $context, 32);

    my $ks = _schedule_from_epoch_secret($epoch_secret,
                                         $args{confirmed_transcript_hash} // '');
    $ks->{joiner_secret} = $joiner_secret;
    return $ks;
}

# 最初の epoch（グループ作成時）。init_secret = 0、commit_secret = 0。
sub initial_key_schedule {
    my (%args) = @_;
    return key_schedule_next(
        init_secret   => $ZERO32,
        commit_secret => $ZERO32,
        psk_secret    => $args{psk_secret} // $ZERO32,
        context       => $args{context},
        confirmed_transcript_hash => $args{confirmed_transcript_hash} // '',
    );
}

sub _schedule_from_epoch_secret {
    my ($epoch_secret, $confirmed_transcript_hash) = @_;

    my %ks = (
        epoch_secret       => $epoch_secret,
        sender_data_secret => derive_secret($epoch_secret, 'sender data'),
        encryption_secret  => derive_secret($epoch_secret, 'encryption'),
        exporter_secret    => derive_secret($epoch_secret, 'exporter'),
        epoch_authenticator => derive_secret($epoch_secret, 'authentication'),
        external_secret    => derive_secret($epoch_secret, 'external'),
        confirmation_key   => derive_secret($epoch_secret, 'confirm'),
        membership_key     => derive_secret($epoch_secret, 'membership'),
        resumption_psk     => derive_secret($epoch_secret, 'resumption'),
        init_secret        => derive_secret($epoch_secret, 'init'),
    );

    $ks{confirmation_tag} = confirmation_tag($ks{confirmation_key}, $confirmed_transcript_hash);
    return \%ks;
}

# コミットの confirmation_tag（HMAC-SHA256）
sub confirmation_tag {
    my ($confirmation_key, $confirmed_transcript_hash) = @_;
    return hmac_sha256($confirmed_transcript_hash, $confirmation_key);
}

# 送信鍵（secret tree から）。DAVE ではハンドシェイクのみなので使わないが、
# 仕様の完全性のため用意する。
sub send_key {
    my ($encryption_secret, $leaf_index, $generation) = @_;
    my $handshake = derive_secret($encryption_secret, 'handshake');
    return expand_with_label($handshake, 'key', pack('N', $generation), 16);
}

# Welcome の GroupInfo 暗号化用の鍵（RFC 9420 §12.4.3）
#   welcome_secret = DeriveSecret(joiner_secret, "welcome")
#   key   = ExpandWithLabel(welcome_secret, "key",   "", KDF.Nh=16)
#   nonce = ExpandWithLabel(welcome_secret, "nonce", "", AEAD.Nn=12)
sub welcome_keys {
    my ($joiner_secret) = @_;
    my $welcome_secret = derive_secret($joiner_secret, 'welcome');
    return {
        key   => expand_with_label($welcome_secret, 'key',   '', 16),
        nonce => expand_with_label($welcome_secret, 'nonce', '', 12),
    };
}

# ---------------------------------------------------------------- DAVE メディアキー

# DAVE の per-sender key ratchet の元秘密。
#   sender_base_secret = MLS-Exporter("Discord Secure Frames v0", littleEndianSenderID, 16)
sub media_key_base_secret {
    my ($exporter_secret, $user_id) = @_;

    my $context = pack 'Q<', $user_id;    # little-endian 64bit
    return mls_exporter($exporter_secret, 'Discord Secure Frames v0', $context, 16);
}

# MLS の sender ratchet（RFC 9420 §9.1 と同じ構造）で generation 番目の鍵を出す。
#   key[n]    = ExpandWithLabel(secret[n], "key",    n, 16)
#   secret[n+1] = ExpandWithLabel(secret[n], "secret", n, 32)
sub sender_ratchet_key {
    my ($base_secret, $generation) = @_;

    my $secret = $base_secret;
    my $key;
    for my $n (0 .. $generation) {
        $key = expand_with_label($secret, 'key', pack('N', $n), 16);
        $secret = expand_with_label($secret, 'secret', pack('N', $n), 32)
            if $n < $generation;
    }
    return $key;
}

1;

__END__

=head1 NAME

Disperl::Voice::Dave::KeySchedule - MLS のキースケジュール

=head1 DESCRIPTION

RFC 9420 §8 のキースケジュールと、DAVE のメディアキー導出
（MLS-Exporter "Discord Secure Frames v0"）を提供する。

=cut
