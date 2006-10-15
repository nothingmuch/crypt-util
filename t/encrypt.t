#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Exception;

use ok "Crypt::Util";

my ( $c, $fallback_cipher );
BEGIN {

	$c = Crypt::Util->new;

	$fallback_cipher = eval { $c->fallback_cipher };

	plan skip_all => "Couldn't load any cipher" if $@ =~ /^Couldn't load any cipher/;

	plan 'no_plan';
}


pass("blah");

