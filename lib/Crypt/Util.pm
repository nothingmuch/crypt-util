#!/usr/bin/perl

package Crypt::Util;

use strict;
use warnings;

use base qw/Class::Accessor::Fast/;

our $VERSION = "0.01_01";

use Digest;
use Storable;

$Digest::MMAP{"RIPEMD160"} ||= $Digest::MMAP{"RIPEMD-160"} ||="Crypt::RIPEMD160";

use Carp qw/croak/;

sub __curry_instance {
	my ($class, $method_name, undef, $col) = @_;

	my $self = $col->{instance} ||= $class->__curry_flavoured_instance($col);

	sub { $self->$method_name(@_) };
}

sub __curry_flavoured_instance {
	my ( $class, $col ) = @_;

	my %params; @params{ map { "default_$_" } keys %{ $col->{defaults} } } = values %{ $col->{defaults} };

	$class->new( \%params );
}

use Sub::Exporter;

BEGIN {
	our @DEFAULT_ACCESSORS = qw/
		mode
		encode
		encoding
		digest
		cipher
		key
		default_uri_encoding
		default_printable_encoding
		use_literal_key
	/;

	__PACKAGE__->mk_accessors( map { "default_$_" } @DEFAULT_ACCESSORS );

	__PACKAGE__->mk_accessors("disable_fallback");

	my %export_groups = (
		'crypt' => [qw/
			encrypt_string decrypt_string
			tamper_protected thaw_tamper_protected tamper_unprotected
			cipher_object
		/],
		digest => [qw/
			digest_string verify_hash verify_digest
			digest_object
		/],
		encoding => [qw/
			encode_string decode_string
			encode_string_hex decode_string_hex
			encode_string_base64 decode_string_base64 encode_string_base64_wrapped
			encode_string_base32 decode_string_base32
			encode_string_uri_base64 decode_string_uri_base64
			encode_string_uri decode_string_uri
			encode_string_alphanumerical decode_string_alphanumerical
			encode_string_printable decode_string_printable
			encode_string_uri_escape decode_string_uri_escape
		/],
		params => [ "exported_instance", "disable_fallback", map { "default_$_" } @DEFAULT_ACCESSORS ],
	);

	my %exports = map { $_ => \&__curry_instance } map { @$_ } values %export_groups;

	Sub::Exporter->import( -setup => {
		exports    => \%exports,
		groups     => \%export_groups,
		collectors => {
			defaults => sub { 1 },
		},
	});
}

our %FALLBACK_LISTS = (
	mode                    => [qw/CFB CBC Ctr OFB/],
	stream_mode             => [qw/CFB Ctr OFB/],
	block_mode              => [qw/CBC/],
	cipher                  => [qw/Rijndael Twofish Blowfish IDEA RC6 RC5/],
	digest                  => [qw/SHA1 SHA256 RIPEMD160 Whirlpool MD5 Haval256/],
	encoding                => [qw/hex/],
	printable_encoding      => [qw/base64 hex/],
	alphanumerical_encoding => [qw/base32 hex/],
	uri_encoding            => [qw/uri_base64 base32 hex/],
);

foreach my $fallback ( keys %FALLBACK_LISTS ) {
	my @list = @{ $FALLBACK_LISTS{$fallback} };

	my $list_method = "fallback_${fallback}_list";

	my $list_method_sub = sub { # derefed list accessors
		my ( $self, @args ) = @_;
		if ( @args ) {
			@args = @{ $args[0] } if @args == 1 and (ref($args[0])||'') eq "ARRAY";
			$self->{$list_method} = \@args;
		}
		@{ $self->{$list_method} || \@list };
	};

	my $type = ( $fallback =~ /(encoding|mode)/ )[0] || $fallback;
	my $try = "_try_${type}_fallback";

	my $fallback_sub = sub {
		my $self = shift;

		$self->_find_fallback(
			$fallback,
			$try,
			$self->$list_method,
		) || croak "Couldn't load any $fallback";
	};

	no strict 'refs';
	*{ "fallback_$fallback" } = $fallback_sub;
	*{ $list_method } = $list_method_sub;
}

{
	my %fallback_caches;
	
	sub _find_fallback {
		my ( $self, $key, $test, @list ) = @_;

		my $cache = $fallback_caches{$key} ||= {};
	
		@list = $list[0] if @list and $self->disable_fallback;

		foreach my $elem ( @list ) {
			$cache->{$elem} = $self->$test( $elem ) unless exists $cache->{$elem};
			return $elem if $cache->{$elem};
		}

		return;
	}
}

sub _try_cipher_fallback {
	my ( $self, $name ) = @_;

	local $@;
	( my $file = "Crypt::${name}.pm" ) =~ s{::}{/}g;
	eval { require $file };
	
	return 1 if !$@;
	die $@ if $@ !~ /^(?:Can|Could)(?: not|n't) (?:instantiate|load|locate) Crypt(?:::$name)?/i;
	return;
}

sub _try_digest_fallback {
	my ( $self, $name ) = @_;

	local $@;
	eval { $self->digest_object( digest => $name ) };

	return 1 if !$@;
	( my $file = $name ) =~ s{::}{/}g;
	die $@ if $@ !~ m{^Can't locate Digest/${file}.pm in \@INC};
	return;
}

sub _try_mode_fallback {
	my ( $self, $mode ) = @_;

	(my $file = "Crypt::${mode}.pm") =~ s{::}{/}g;

	local $@;
	eval { require $file }; # yes it's portable

	return 1 if !$@;
	die $@ if $@ !~ /^Can't locate $file in \@INC/;
	return;
}

{
	my %encoding_module = (
		base64     => "MIME::Base64",
		uri_base64 => "MIME::Base64",
		base32     => "MIME::Base32",
		uri_escape => "URI::Escape",
	);

	sub _try_encoding_fallback {
		my ( $self, $encoding ) = @_;	

		return 1 if $encoding eq "hex";
		
		my $module = $encoding_module{$encoding};
		$module =~ s{::}{/}g;
		$module .= ".pm";

		local $@;
		eval { require $module };

		return !$@;
	}
}

sub _args (\@;$) {
	my ( $args, $odd ) = @_;

	my ( $self, @args ) = @$args;

	my %params;
	if ( @args % 2 == 1 ) {
		croak "The parameters must be an even sized list of key value pairs" unless defined $odd;
		( my $odd_value, %params ) = @args;
		croak "Can't provide the positional param in the named list as well" if exists $params{$odd};
		$params{$odd} = $odd_value;
	} else {
		%params = @args;
	}

	return ( $self, %params );
}

sub _process_params {
	my ( $self, $params, @required ) = @_;

	foreach my $param ( @required ) {
		next if exists $params->{$param};

		$params->{$param} = $self->_process_param( $param );
	}
}

sub _process_param {
	my ( $self, $param ) = @_;

	my $default = "default_$param";

	if ( $self->can($default) and defined( my $value = $self->$default ) ) {
		return $value;
	}

	my $fallback = "fallback_$param";
	if ( $self->can($fallback) ) {
		return $self->$fallback;
	} else {
		croak "No default value for required parameter '$param'";
	}
}

sub cipher_object {
	my ( $self, %params ) = _args @_;
	
	$self->_process_params( \%params, qw/mode/);

	my $method = "cipher_object_" . lc(delete $params{mode});

	$self->$method( %params );
}

sub cipher_object_cbc {
	my ( $self, %params ) = _args @_;

	$self->_process_params( \%params, qw/cipher/ );

	require Crypt::CBC;

	Crypt::CBC->new(
		-cipher      => $params{cipher},
		-key         => $self->process_key(%params),
	);
}

sub cipher_object_ofb {
	my ( $self, %params ) = _args @_;

	$self->_process_params( \%params, qw/cipher/ );

	require Crypt::OFB;
	my $c = Crypt::OFB->new;

	$c->padding( Crypt::ECB::PADDING_AUTO() );

	$c->key( $self->process_key(%params) );

	$c->cipher( $params{cipher} );

	return $c;
}

sub cipher_object_cfb {
	my ( $self, @args ) = _args @_;
	require Crypt::CFB;
	$self->_cipher_object_baurem( "Crypt::CFB", @args );
}

sub cipher_object_ctr {
	my ( $self, @args ) = _args @_;
	require Crypt::Ctr;
	$self->_cipher_object_baurem( "Crypt::Ctr", @args );
}

sub _cipher_object_baurem {
	my ( $self, $class, %params ) = @_;

	my $prefix = "Crypt";
	( $prefix, $params{cipher} ) = ( Digest => delete $params{digest} ) if exists $params{digest};

	$self->_process_params( \%params, qw/cipher/ );

	$class->new( $self->process_key(%params), join("::", $prefix, $params{cipher}) );
}

use tt;
[% FOR mode IN ["stream", "block"] %]
sub cipher_object_[% mode %] {
	my ( $self, @args ) = _args @_;
	my $mode = $self->_process_param("[% mode %]_mode");
	$self->cipher_object( @args, mode => $mode );
}
[% END %]
no tt;

sub process_key {
	my ( $self, %params ) = _args @_, "key";

	if ( $params{literal_key} || $self->default_use_literal_key ) {
		$self->_process_params( \%params, qw/key/ );
		return $params{key};
	} else {
		$self->_process_params( \%params, qw/key cipher/ );
		my $cipher = $params{cipher};

		my $class = "Crypt::$cipher";
		my $size_method = $class->can("keysize") || $class->can("blocksize");
		my $size = $class->$size_method;

		$size ||= $cipher eq "Blowfish" ? 56 : 32;

		return $self->digest_string(
			string => $params{key},
			digest => "MultiHash",
			encode => 0,
			digest_args => [{
				width  => $size,
				hashes => [ $self->fallback_digest_list ],
			}],
		);
	}
}

sub digest_object {
	my ( $self, %params ) = _args @_;

	$self->_process_params( \%params, qw/
		digest
	/);

	Digest->new( $params{digest}, @{ $params{digest_args} || [] } );
}

use tt;
[% FOR f IN ["en", "de"] %]
sub [% f %]crypt_string {
	my ( $self, %params ) = _args @_, "string";

	my $string = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $string;

	my $c = $self->cipher_object( %params );

	[% IF f == "en" %]
	$self->_maybe_encode( $c->encrypt($string), \%params );
	[% ELSE %]
	$c->decrypt( $self->_maybe_decode($string, \%params ) );
	[% END %]
}

sub _maybe_[% f %]code {
	my ( $self, $string, $params ) = @_;

	my $should_encode = exists $params->{[% f %]code}
		? $params->{[% f %]code}
		: exists $params->{encoding} || $self->default_encode;

	if ( $should_encode ) {
		return $self->[% f %]code_string(
			%$params,
			string   => $string,
		);
	} else {
		return $string;
	}
}
[% END %]
no tt;

sub digest_string {
	my ( $self, %params ) = _args @_, "string";

	my $string = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $string;

	my $d = $self->digest_object( %params );

	$d->add($string);

	$self->_maybe_encode( $d->digest, \%params );
}

sub verify_hash {
	my ( $self, %params ) = _args @_;

	my $hash = delete $params{hash};
	my $fatal = delete $params{fatal};
	croak "You must provide the 'string' and 'hash' parameters" unless defined $params{string} and defined $hash;

	return 1 if $hash eq $self->digest_string( %params );

	if ( $fatal ) {
		croak "Digest verification failed";
	} else {
		return;
	}
}

sub verify_digest {
	my ( $self, @args ) = @_;
	$self->verify_hash(@args);
}

my @flags = qw/storable/;
our $TAMPER_PROTECT_VERSION = 1;

sub tamper_protected {
	my ( $self, %params ) = _args @_, "data";

	$self->_process_params( \%params, qw/
		data
	/);

	my $data = delete $params{data};

	my %flags;

	if ( ref $data ) {
		$flags{storable} = 1;
		$data = Storable::nfreeze($data);
	}

	my $flags = $self->_flag_hash_to_int(%flags);

	my $packed = pack("n n N/a*", $TAMPER_PROTECT_VERSION, $flags, $data );

	# FIXME HMAC etc here

	my $hash = $self->digest_string(
		%params,
		encode => 0,
		string => $packed,
	);

	return $self->encrypt_string(
		%params,
		string => pack("n/a* a*", $hash, $packed),
	);
}

sub _flag_hash_to_int {
	my ( $self, %flags ) = @_;

	my $bit = 1;
	my $flags = 0;

	foreach my $flag (@flags) {
		$flags |= $bit if $flags{$flag};
	} continue {
		$bit *= 2;	
	}

	return $flags;
}

sub thaw_tamper_protected {
	my ( $self, %params ) = _args @_, "string";

	my $hashed_packed = $self->decrypt_string( %params );

	my ( $hash, $version, $flags, $packed ) = unpack("n/a n n X[n n] a*", $hashed_packed);

	$self->_tamper_protect_version_check( $version );

	my %flags = $self->_flag_int_to_hash($flags);

	return unless $self->verify_hash(
		fatal  => 1,
		%params, # allow user to override fatal
		hash   => $hash,
		decode => 0,
		string => $packed,
	);

	my $data = unpack("x[n n] N/a*", $packed);

	return $flags{storable}
		? Storable::thaw($data)
		: $data;
}

sub tamper_unprotected {
	my ( $self, @args ) = @_;
	$self->thaw_tamper_protected(@args);
}

sub _tamper_protect_version_check {
	my ( $self, $version ) = @_;

	croak "Incompatible tamper protected string (I'm version $TAMPER_PROTECT_VERSION, thawing version $version)"
		unless $version == $TAMPER_PROTECT_VERSION;
}

sub _flag_int_to_hash {
	my ( $self, $flags ) = @_;

	my $bit =1;
	my %flags;

	foreach my $flag (@flags ) {
		$flags{$flag} = $flags & $bit;
	} continue {
		$bit *= 2;
	}

	return wantarray ? %flags : \%flags;
}

use tt
[% FOR f IN ["en","de"] %]
sub [% f %]code_string {
	my ( $self, %params ) = _args @_, "string";

	my $string = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $string;

	$self->_process_params( \%params, qw/
		encoding
	/);

	my $encoding = delete $params{encoding};
	croak "Encoding method must be an encoding name" unless $encoding;
	my $method = "[% f %]code_string_$encoding";
	croak "Encoding method $encoding is not supported" unless $self->can($method);

	$self->$method($string);
}
[% END %]
no tt;

sub encode_string_hex {
	my ( $self, $string ) = @_;
	unpack("H*", $string);
}

sub decode_string_hex {
	my ( $self, $hex ) = @_;
	pack("H*", $hex );
}

sub encode_string_base64 {
	my ( $self, $string ) = @_;
	require MIME::Base64;
	MIME::Base64::encode_base64($string, "");
}

sub encode_string_base64_wrapped {
	my ( $self, $string ) = @_;
	require MIME::Base64;
	MIME::Base64::encode_base64($string);
}

sub decode_string_base64 {
	my ( $self, $base64 ) = @_;
	require MIME::Base64;
	MIME::Base64::decode_base64($base64);
}

# http://www.dev411.com/blog/2006/10/02/encoding-hashed-uids-base64-vs-hex-vs-base32
sub encode_string_uri_base64 {
	my ( $self, $string ) = @_;
	my $encoded = $self->encode_string_base64($string);
	$encoded =~ tr{+/}{*-};
	$encoded =~ s/=+$//;
	return $encoded;
}

sub decode_string_uri_base64 {
	my ( $self, $base64 ) = @_;
	$base64 =~ tr{*-}{+/};
	$self->decode_string_base64($base64);
}

sub encode_string_base32 {
	my ( $self, $string ) = @_;
	require MIME::Base32;
	MIME::Base32::encode_rfc3548($string);
}

sub decode_string_base32 {
	my ( $self, $base32 ) = @_;
	require MIME::Base32;
	MIME::Base32::decode_rfc3548(uc($base32));
}

sub encode_string_uri_escape {
	my ( $self, $string ) = @_;
	require URI::Escape;
	URI::Escape::uri_escape($string);
}

sub decode_string_uri_escape {
	my ( $self, $uri_escaped ) = @_;
	require URI::Escape;
	URI::Escape::uri_unescape($uri_escaped);
}

use tt;
[% FOR symbolic_encoding IN ["uri", "alphanumerical", "printable"] %]
[% FOR f IN ["en", "de"] %]
sub [% f %]code_string_[% symbolic_encoding %] {
	my ( $self, $string ) = @_;
	my $encoding = $self->_process_param("[% symbolic_encoding %]_encoding");
	$self->[% f %]code_string( string => $string, encoding => $encoding );
}
[% END %]
[% END %]
no tt;

sub exported_instance {
	my $self = shift;
	return $self;
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Crypto::Util - A lightweight Crypt/Digest convenience API

=head1 SYNOPSIS

	use Crypto::Util; # also has a Sub::Exporter to return functions wrapping a default instance

	my $util = Crypto::Util->new;

	$util->default_key("my secret");

	# MAC or cipher+digest based tamper resistent encapsulation

	my $tamper_resistent_string = $util->tamper_protected( $data ); # can also take refs

	my $trusted = $util->thaw_tamper_protected( $untrusted_string, key => "another secret" );

	# without specifying which encoding returns base32 or hex if base32 is unavailable
	my $encoded = $util->encode_string( $bytes );

	my $hash = $util->digest( $bytes, digest => "md5" );

	die "baaaad" unless $util->verify_hash(
		hash => $hash,
		data => $bytes,
		digest => "md5",
	);

=head1 ACHTUNG!

This is a sloppy release. By 0.01 the docs should be in place, as well as some
more features I want in. As the saying goes, release prematurely, cry often.

=head1 DESCRIPTION

This module provides an easy, intuitive and forgiving API for weilding
crypto-fu.

Features which are currently missing but are scheduled for 0.01:

=over 4

=item *

xMAC support

=item *

Bruce Schneier Fact Database

=item *

Entropy fetching (get N weak/strong bytes, etc) from e.g. OpenSSL bindings,
/dev/*random, and EGD.

=item *

Pipelined encrypting/digesting... Currently all the methods are named
foo_string. In the future, a foo variant that auto DWIMs will be added, and a
foo_stream, foo_handle, foo_callbacks api will be layered over a simple push
API (like Crypt::CBC).

=back

=head1 PRIORITIES

=over 4

=item Ease of use

Usability patches are very welcome - this is supposed to be an easy api for
random people to be able to easily (but responsibly) use the more low level
Crypt:: and Digest:: modules on the CPAN.

=item Pluggability

Dependency hell is avoided using a fallback mechanism that tries to choose an
algorithm based on an overridable list.

For "simple" use install Crypt::Util and your favourite digest, cipher and
cipher mode (CBC, CFB, etc).

To ensure predictable behavior the fallback behavior can be disabled as necessary.

=back

=head1 METHODS

=over 4

=item tamper_protected [ $data ] %params

=item thaw_tamper_protected [ $string ] %params

=item tamper_unprotected [ $string ] %params

params: data => $anything, encrypt => bool || alg (defaults to true, false means just hmac), key (encrypt_string), digest => bool || alg, encode => bool || alg (defaults to true/"uri", see encode string), fatal => bool (defaults to true, turning it off will return undef on failure instead of dying)

with odd args the first is treated as data

implicitly storables data if it's a ref

=item encrypt_string [ $string ] %params

=item decrypt_string [ $string ] %params

encode => bool || alg (defaults to false), encrypt => bool || alg, key (defaults to server_key)

with odd args the firstr is treated as the string

=item cipher_object %params

params: cipher, key

Return an object using L<Crypt::CBC>

=item digest_string [ $string ] %params

digest => alg

with odd args the firstr is treated as the string

=item verify_digest

hash => string (the hash to verify), string => string (the digested string), all params of digest_string, fatal => bool (defaults to false)

just calls digest_string and then eq

=item digest_object %params

params: digest

Returns an object using L<Digest>

=item encode_string [ $string ] %params

=item decode_string [ $string ] %params

encoding => symbolic type (uri, printable) or concrete type (none, hex, base64, base32)

=item mac_digest_string [ $string ] %params

=item verify_mac %params

XXX emac, hmac, etc wrapper?

mac => string (the mac to verify), string => string (the digested string), type => "digest" || "cipher" # hmac or cmac, fatal => bool (defaults to false, whbich just returns undef on failure)

=item hmac_digest_string %params

=item verify_hmac %params

mac => string (the mac to verify), string => string (the digested string), fatal => bool (defaults to false), all params of hmac_digest_string

=item cmac_digest_string %params

=item verify_cmac

cmac, emac

with odd args the firstr is treated as the string

=item weak_random_string %params

A fairly entropic random string, suitable for digesting

digest => bool || alg (defaults to true), encode bool || alg

=item strong_random_string %params

digest => bool || alg (defaults to false), encode bool || alg, bytes => $n (defaults to 32)

might not be supported (tries /dev/random  and/or the OpenSSL bindings)

=item encode_string_alphanumerical $string

=item decode_string_alphanumerical $string

=item encode_string_uri $string

=item decode_string_uri $string

encoding into a URI safe string

=item encode_string_printable $string

=item decode_string_printable $string

=item encode_string_hex $string

=item decode_string_hex $string

=item encode_string_uri_escape $string

=item decode_string_uri_escape $string

=item encode_string_base64 $string

=item decode_string_base64 $string

=item encode_string_base32 $string

=item decode_string_base32 $string

# "default" is there to be overridden by configs, if it returns nothing fallback will be called
# "fallback" is for when nothing is configured -- the class's default

=item disable

When true only the first item from the fallback list will be tried, and if it
can't be loaded there will be loud deaths.

Enable this to ensure portability

=item default_key

=item default_cipher

=item fallback_cipher

find the first from fallback_cipher_list

=item fallback_cipher_list

qw/Rijndael Twofish Blowfish IDEA RC6 RC5/;

=item default_digest

=item fallback_digest

=item fallback_digest_list

qw/SHA1 RIPEMD-160 Whirlpool MD5/

=item default_encoding

=item fallback_encoding

=item fallback_encoding_list

"hex"

=item default_alphanumerical_encoding

=item fallback_alphanumerical_encoding

=item fallback_alphanumerical_encoding_list

"base32", "hex"

=item default_uri_encoding

=item fallback_uri_encoding

=item fallback_uri_encoding_list

"uri_base64" # XXX make this uri_escape?

=item default_printable_encoding

=item fallback_printable_encoding

"base64"

=back

=cut


