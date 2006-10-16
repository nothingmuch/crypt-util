#!/usr/bin/perl -w

use strict;

use inc::Module::Install;

name 'Crypt-Util';

requires 'Class::Accessor::Fast' => 0;
requires 'Digest'                => 0;
requires 'Sub::Exporter'         => 0;
requires 'Storable'              => 0;

build_requires 'Test::More'      => 0;
build_requires 'Test::use::ok'   => 0;
build_requires 'Test::Exception' => 0;

recommends 'Crypt::CFB' => 0; # stream ciphers
recommends 'Crypt::CBC' => 0; # block ciphers

recommends 'Crypt::Rijndael' => 0; # AES
recommends 'Crypt::Serpent'  => 0; # AES finalist
recommends 'Crypt::Twofish'  => 0; # AES finalist
recommends 'Crypt::RC6'      => 0; # AES finalist
recommends 'Crypt::Blowfish' => 0; # still widely in use
recommends 'Crypt::DES'      => 0; # still widely in use

# Digest::MultiHash requires SHA-1
# Crypt::Utils requires SHA-512 for key munging
unless ( eval { require Digest::SHA } or eval { require Digest::SHA2 } ) {
	# PurePerl will do (Digest::MoreFallbacks)
	unless ( eval { require Digest::SHA::PurePerl } ) {
		requires "Digest::SHA::PurePerl" => 0
	}

	# But for performance Digest::SHA is preferred
	recommends 'Digest::SHA' => 0;
}

recommends 'Crypt::RIPEMD160'  => 0; # it's hip
recommends 'Digest::Whirlpool' => 0; # it's happenning
recommends 'Digest::MD5'       => 0; # it's still alive =(

license "MIT";

all_from 'lib/Crypt/Util.pm';

sign;

WriteAll;



