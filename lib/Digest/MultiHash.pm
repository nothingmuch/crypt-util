#!/usr/bin/perl

package Digest::MultiHash;

use strict;
use warnings;

use base qw/Class::Accessor::Fast Digest::base/;

use Digest;
use Digest::MoreFallbacks;

__PACKAGE__->mk_accessors(qw/__digest_objects width hashes/);

sub _digest_objects {
	my $self = shift;

	@{ $self->__digest_objects || do {
		my @digests = map { eval { Digest->new($_) } || () } @{ $self->hashes || [qw/Whirlpool SHA1 SHA256 Tiger Haval256 MD5/] };
		die "Can't find any digest module" unless @digests;
		@digests = @digests[0 .. 2] if @digests > 3 and !$self->hashes; # if it's defaults limit to 3
   		$self->__digest_objects(\@digests);
	} };
}

sub clone {
	my $self = shift;
	$self->new({
		width => $self->width,
		hashes => $self->hashes,
		( $self->__digest_objects ? ( __digest_objects => [map { $_->clone } @{ $self->__digest_objects }] ) : () ),
	});
}

sub add {
	my ( $self, @args ) = @_;
	$_->add(@args) for $self->_digest_objects;
}

sub digest {
	my $self = shift;
	
	my $width = $self->width;

	my ( $buf, @pieces ) = unpack "(a$width)*", join "", my @digests = map { $_->digest } $self->_digest_objects;

	die "Chosen hashes are insufficient for desired width" if !@pieces and length($buf) < $width;

	$buf ^= $_ for @pieces;

	return $buf;
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Digest::MultiHash - Generalized Digest::SV1

=head1 SYNOPSIS

	use Digest::MultiHash;

=head1 DESCRIPTION

=cut


