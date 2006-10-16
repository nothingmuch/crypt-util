#!/usr/bin/perl

package Digest::MultiHash;

use strict;
use warnings;

use base qw/Class::Accessor::Fast Digest::base/;

use Carp qw/croak/;

use Digest;
use Digest::MoreFallbacks;
use Scalar::Util qw/blessed/;

__PACKAGE__->mk_accessors(qw/_digest_objects width/);
__PACKAGE__->mk_ro_accessors(qw/hashes/);

sub new {
	my ( $class, @params ) = @_;

	if ( @params != 1 ) {
		croak "You must supply an even sized list or a single hash reference to new" unless @params % 2 == 0;
		@params = { @params };
	}

	if ( (ref($params[0])||'') ne "HASH" ) {
		croak "You must supply an even sized list or a single hash reference to new";
	}

	my $self = $class->SUPER::new( @params );
	
	$self->_create_digest_objects;

	return $self;
}

sub _call {
	my ( $self, $method, @args ) = @_;
	map { $_->$method( @args ) } @{ $self->_digest_objects };
}

sub _create_digest_objects {
	my $self = shift;

	my @digests = map {
		blessed($_)
			? $_
			: Digest->new(
				((ref($_)||'') eq "ARRAY")
					? @$_
					: $_
			)
	} @{ $self->hashes || [qw/SHA-1/] };

	die "No digest module specified" unless @digests;

	$self->_digest_objects(\@digests);
}

sub clone {
	my $self = shift;
	$self->new({
		width => $self->width,
		hashes => $self->hashes,
		_digest_objects => [ $self->_call("clone") ],
	});
}

sub add {
	my ( $self, @args ) = @_;
	$self->_call("add", @args);
}

sub digest {
	my $self = shift;

	my @digests = $self->_call("digest");
	
	my $width = $self->width || length($digests[0]);

	my $concat = join "", @digests;
	
	die "Chosen hashes are insufficient for desired width" if length($concat) < $width;

	my ( $buf, @pieces ) = unpack "(a$width)*", $concat;

	$buf ^= $_ for @pieces;

	return $buf;
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Digest::MultiHash - XOR based, variable width multiplexing of hashes (a
generalized Digest::SV1).

=head1 SYNOPSIS

	use Digest::MultiHash;

	my $d = Digest::Multihash->new(
		width => 16, # bytes
		hashs => ["SHA-512", "Whirlpool"], # see below for arbitrary arguments
	);

	$d->add($data);

	print $d->hexdigest;

=head1 DESCRIPTION

This class inherits from L<Digest::base>, and provides generalized digest
multiplexing.

It will multiplex all calls to C<add> to all of it's sub digest objects.
Likewise, when the final digest is extracted the digests will be extracted and
then XOR'd over eachother according to C<width>.

C<width> will default to the width of the first hash if unspecified.

C<hashes> defaults to C<SHA-1> for compatibility reasons.

This module is useful for generating keys from passphrases, by supplying the
desired width and simply making sure there is enough data from the combined
hashes.

=head1 METHODS

See L<Digest> for the complete API. This module inherits from L<Digest::base>.

=over 4

=item new

This methods accepts a hash reference or an even sized list of parameters named
according to the methods.

=item add

=item digest

Compute the hash by calling C<digest> on all of the subhashes, splitting the
result up into C<width> sized chunk, and then XORing these together.

If the result is not aligned on C<width> the result will not be truncated. The
shorter string will still be XOR'd with the hash, even if this only affects
part of the result.

If there are not at least C<width> bytes of data in the output of the combined
hashes an error is thrown.

=item clone

Clones the hash.

=item hashes

Get the array of hashes to use. Array values in this will be dereferenced
before the call to L<Digest/new> to allow passing of arbitrary arguments.
Blessed objects (of any class) will be used verbatim.

The list of hashes cannot be changed after construction.

=item width

Get/set the byte-width to use.

=back

=head1 SEE ALSO

L<Digest>, L<Digest::SV1>, L<Digest::SHA1>

=cut


