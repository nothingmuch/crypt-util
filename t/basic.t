#!/usr/bin/perl

use strict;
use warnings;

use Test::More 'no_plan';

use ok "Crypt::Util";

can_ok "Crypt::Util" => qw/
	cipher_object
	digest_object
/;

my $c = Crypt::Util->new;

isa_ok( $c, "Crypt::Util" );

is( $c->default_cipher, undef, "no default cipher" );

my $fallback_cipher = eval { $c->fallback_cipher };

SKIP: {
	skip "Couldn't load any cipher", 4 if $@ =~ /^Couldn't load any cipher/;

	ok( !$@, "no unexpected error" );
	ok( defined($fallback_cipher), "fallback defined" );

	my $cipher = $c->cipher_object( key => "foo" );

	can_ok( $cipher, qw/encrypt decrypt/ );
	is( $cipher->decrypt( $cipher->encrypt("foo") ), "foo", "round trip encryption" );
}


is( $c->default_digest, undef, "no default digest" );

my $fallback_digest = eval { $c->fallback_digest };

SKIP: {
	skip "Couldn't load any digest", 4 if $@ =~ /^Couldn't load any digest/;

	ok( !$@, "no unexpected error" );
	ok( defined($fallback_digest), "fallback defined" );

	my $digest = $c->digest_object;

	can_ok( $digest, qw/add digest/ );

	$digest->add("foo");

	my $foo_digest = $digest->digest;

	$digest->add("bar");

	my $bar_digest = $digest->digest;

	cmp_ok( $foo_digest, "ne", $bar_digest, "digests differ" );

}


