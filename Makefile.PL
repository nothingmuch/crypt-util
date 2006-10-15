#!/usr/bin/perl -w

use strict;

use inc::Module::Install;

name 'Crypt-Util';

requires 'Class::ACcessor::Fast' => 0;
requires 'Digest'                => 0;
requires 'Sub::Exporter'         => 0;
requires 'Storable'              => 0;

build_requires 'Test::More'      => 0;
build_requires 'Test::use::ok'   => 0;
build_requires 'Test::Exception' => 0;

recommends 'Crypt::CFB' => 0;
recommends 'Crypt::CBC' => 0;

recommends 'Crypt::Rijndael' => 0;
recommends 'Crypt::Twofish'  => 0;
recommends 'Crypt::Blowfish' => 0;

recommends 'Digest::SHA1'      => 0;
recommends 'Digest::SHA2'      => 0;
recommends 'Digest::Whirlpool' => 0;
recommends 'Digest::MD5'       => 0;

license "MIT";

all_from 'lib/Crypt/Util.pm';

sign;

WriteAll;



