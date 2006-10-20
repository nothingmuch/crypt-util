#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Exception;

use ok "Crypt::Util";

my $c;
BEGIN {

	$c = Crypt::Util->new;

	eval { $c->fallback_digest; $c->fallback_cipher };
	plan skip_all => "Couldn't load digest/cipher" if $@ =~ /^Couldn't load any (cipher|digest)/;

	plan 'no_plan';
}

$c->default_key("foo");

foreach my $encrypted ( 1, 0 ) {

	foreach my $data (
		"zemoose gauhy tj lkj GAJE E djjjj laaaa di da dooo",
		{ foo => "bar", gorch => [ qw/very deep/, 1 .. 10 ] },
		"\0 bar evil binary string \0 \0\0 foo la \xff foo \0 bar",
	) {

		my $tamper = $c->tamper_proof( data => $data, encrypt => $encrypted );

		unless ( ref $data ) {
			if ( $encrypted ) {
				unlike( $tamper, qr/\Q$data/, "tamper proof does not contain the original" )
			} else {
				like( $tamper, qr/\Q$data/, "tamper proof contains the original" )
			}
		}

		my $thawed = $c->thaw_tamper_proof( string => $tamper );

		is_deeply( $thawed, $data, "tamper resistence round trips (" . ($encrypted ? "encrypted/digested" : "mac signed") .")" );

		my $corrupt_tamper = $tamper;
		substr( $corrupt_tamper, -10, 5 ) ^= "moose";

		throws_ok {
			$c->thaw_tamper_proof( string => $corrupt_tamper );
		} qr/verification failed/, "corrupt tamper proof string failed";

		my $twaddled_tamper;
		if ( $encrypted ) {
			my ( $type, $inner ) = $c->_unpack_tamper_proof($tamper);
			$twaddled_tamper = $c->decrypt_string( string => $inner );
			substr( $twaddled_tamper, -10, 5 ) ^= "moose";
			$twaddled_tamper = $c->_pack_tamper_proof($type, $c->encrypt_string( string => $twaddled_tamper ));
		} else {
			$twaddled_tamper = $tamper;
			substr( $twaddled_tamper, -10, 5 ) ^= "moose";
		}

		throws_ok {
			$c->thaw_tamper_proof( string => $twaddled_tamper );
		} qr/verification failed/, "altered tamper proof string failed";

		local $Crypt::Util::TAMPER_PROOF_VERSION = -1;

		throws_ok {
			$c->thaw_tamper_proof( string => $tamper );
		} qr/Incompatible tamper proof string/, "version check";
	}

}
