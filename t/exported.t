#!/usr/bin/perl

use strict;
use warnings;

use Test::More 'no_plan';

use ok 'Crypt::Util' => (
	qw/:crypt default_key exported_instance/,
	defaults => {
		key => "moose",
	},
);

is( default_key, "moose", "default key set through defaults" );

default_key("bar");

is( default_key, "bar", "can be used as a setter, too" );

isa_ok( exported_instance, "Crypt::Util" );

like(
	encrypt_string( string => "moose", encode => 1 ),
	qr/^[a-f0-9]+$/,
	"encrypt + encode",
);

