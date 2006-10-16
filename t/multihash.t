#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use Digest::MultiHash;

BEGIN {
	plan skip_all => "No hash modules found"
		unless eval { Digest::MultiHash->new }
			and $@ !~ /^Can't find any digest module/;

	plan tests => 2;
}

my $d = Digest::MultiHash->new;

isa_ok( $d , "Digest::base" );

$d->width( 8 );

$d->add("foo bar gorch");

my $d2 = Digest::MultiHash->new({ width => 8 });

$d2->add("foo bar moose");

cmp_ok( $d->digest, "ne", $d2->digest, "digests differ" );
