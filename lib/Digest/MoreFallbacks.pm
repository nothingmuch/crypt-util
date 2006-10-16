#!/usr/bin/perl

package Digest::MoreFallbacks;

use strict;
use warnings;

push @{ $Digest::MMAP{"RIPEMD160"} ||= $Digest::MMAP{"RIPEMD-160"} ||= [] }, "Crypt::RIPEMD160";

foreach my $sha (1, 224, 256, 384, 512) {
	push @{ $Digest::MMAP{"SHA$sha"} ||= $Digest::MMAP{"SHA-$sha"} ||= [] }, ["Digest::SHA::PurePerl", $sha];
}

push @{ $Digest::MMAP{"MD5"} ||= [] }, "Digest::MD5", "Digest::Perl::MD5";

__PACKAGE__;

__END__

=pod

=head1 NAME

Digest::MoreFallbacks - Provide additional fallbacks in L<Digest>'s MMAP table.

=head1 SYNOPSIS

	use Digest::MoreFallbacks;

	Digest->new("SHA-1")

=head1 DESCRIPTION

This module adds entries to L<Digest>'s algorithm to implementation table. The
intent is to provide better fallback facilities, including pure Perl modules
(L<Digest::SHA::PurePerl>, L<Digest::MD5>), and facilitating for modules that
don't match the naming convention (L<Crypt::RIPEMD160> would have worked if it
were named L<Digest::RIPEMD160>).

=cut


