#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Exception;

use ok "Crypt::Util";

my ( $c, $fallback_digest );
BEGIN {

	$c = Crypt::Util->new;

	$fallback_digest = eval { $c->fallback_digest };

	plan skip_all => "Couldn't load any digest" if $@ =~ /^Couldn't load any digest/;

	plan 'no_plan';
}

my $string = "magic moose";

my $hash = $c->digest_string( string => $string );

ok(
	eval {
		$c->verify_hash(
			hash   => $hash,
			string => $string,
		);
	},
	"verify digest",
);

ok( !$@, "no error" ) || diag $@;

ok(
	eval {
		!$c->verify_hash(
			hash   => $hash,
			string => "some other string",
		);
	},
	"verify bad digest",
);

ok( !$@, "no error" ) || diag $@;

throws_ok {
	$c->verify_hash(
		hash   => $hash,
		string => "some other string",
		fatal  => 1,
	),
} qr/verification failed/, "verify_hash with fatal => 1";

SKIP: {
	eval { require Digest::MD5 };
	skip "Digest::MD5 couldn't be loaded", 3 if $@;
	skip "Digest::MD5 is the only fallback", 3 if $fallback_digest eq "SHAMD5";

	my $md5_hash = $c->digest_string(
		digest => "MD5",
		string => $string,
	);

	cmp_ok( $md5_hash, "ne", $hash, "$fallback_digest hash ne MD5 hash" );

	ok(
		!$c->verify_hash(
			hash   => $md5_hash,
			string => $string,
		),
		"verification fails without same digest",
	);

	ok(
		$c->verify_hash(
			hash   => $md5_hash,
			string => $string,
			digest => "MD5",
		),
		"verification succeeds when MD5",
	);
}

