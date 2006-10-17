#!/usr/bin/perl

package Crypt::Util;

use strict;
use warnings;

use base qw/Class::Accessor::Fast/;

our $VERSION = "0.01_02";

use Digest;
use Digest::MoreFallbacks;

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
	cipher                  => [qw/Rijndael Serpent Twofish Blowfish RC6 RC5/],
	digest                  => [qw/SHA-1 SHA-256 RIPEMD160 Whirlpool MD5 Haval256/],
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
	$self->_try_loading_module("Crypt::$name");
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
	$self->_try_loading_module("Crypt::$mode");
}

sub _try_mac_fallback {
	my ( $self, $mac ) = @_;
	$self->_try_loading_module("Digest::$mac");
}

sub _try_loading_module {
	my ( $self, $name ) = @_;

	(my $file = "${name}.pm") =~ s{::}{/}g;

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
	( $prefix, $params{cipher} ) = ( Digest => delete $params{digest} ) if exists $params{encryption_digest};

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
		my $size = $params{key_size};

		unless ( $size ) {
			$self->_process_params( \%params, qw/key cipher/ );
			my $cipher = $params{cipher};

			my $class = "Crypt::$cipher";
			my $size_method = $class->can("keysize") || $class->can("blocksize");
			$size = $class->$size_method;

			$size ||= $cipher eq "Blowfish" ? 56 : 32;
		}

		return $self->digest_string(
			string => $params{key},
			digest => "MultiHash",
			encode => 0,
			digest_args => [{
				width  => $size,
				hashes => ["SHA-512"], # no need to be overkill, we just need the variable width
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
		require Storable;
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

	if ( $flags{storable} ) {
		require Storable;
		return Storable::thaw($data);
	} else {
		return $data;
	}
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
	$base64 .= "=" x abs( - length($base64) % 4 );
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

Crypt::Util - A lightweight Crypt/Digest convenience API

=head1 SYNOPSIS

	use Crypto::Util; # also has a Sub::Exporter to return functions wrapping a default instance

	my $util = Crypto::Util->new;

	$util->default_key("my secret");

	# MAC or cipher+digest based tamper resistent encapsulation
	# (uses Storable on $data if necessary)
	my $tamper_resistent_string = $util->tamper_protected( $data );

	my $verified = $util->thaw_tamper_protected( $untrusted_string, key => "another secret" );

	# If the encoding is unspecified, base32 is used
	# (hex if base32 is unavailable)
	my $encoded = $util->encode_string( $bytes );

	my $hash = $util->digest( $bytes, digest => "md5" );

	die "baaaad" unless $util->verify_hash(
		hash   => $hash,
		data   => $bytes,
		digest => "md5",
	);


=head1 DESCRIPTION

This module provides an easy, intuitive and forgiving API for wielding
crypto-fu.

=head2 Priorities

=over 4

=item Ease of use

This module is designed to have an easy API to allow easy but responsible
use of the more low level Crypt:: and Digest:: modules on CPAN.  Therefore,
patches to improve ease-of-use are very welcome.

=item Pluggability

Dependency hell is avoided using a fallback mechanism that tries to choose an
algorithm based on an overridable list.

For "simple" use install Crypt::Util and your favourite digest, cipher and
cipher mode (CBC, CFB, etc).

To ensure predictable behavior the fallback behavior can be disabled as necessary.

=back

=head2 Interoperability

To ensure that your hashes and strings are compatible with L<Crypt::Util>
deployments on other machines (where different Crypt/Digest modules are
available, etc) you should use C<disable_fallback>.

Then either set the default ciphers, or always explicitly state the cipher.

If you are only encrypting and decrypting with the same installation, and new
cryptographic modules are not being installed, the hashes/ciphertexts should be
compatible without disabling fallback.

=head1 METHODS


# FIXME
# missing:
# process_key, default_mode, fallback_mode, fallback_mode_list
=over 4

=item tamper_protected( [ $data ], %params )

# DESCRIBE

=item thaw_tamper_protected( [ $string ], %params )

# DESCRIBE

=item tamper_unprotected( [ $string ], %params )

This method accepts the following parameters:

=over 4

=item * data

The data to encrypt. If this is a reference L<Storable> will be used to serialize the data.

=item * encrypt

By default this parameter is true, unless C<default_tamper_protect_encrypts()>,
has been used to alter it.

A true value implies that all the parameters
which are available to C<encrypt_string()> are also available.  If a
negative value is specified, MAC mode is used, and the additional
parameters of C<mac_string()> may also be specified to this method.,

=back


=item encrypt_string( [ $string ], %params )

All of the parameters which may be supplied to C<process_key()> are
also available to this method.

=item decrypt_string( [ $string ], %params )

The following parameters may be used:

=over 4

=item * encode

Boolean.  The default value is false.

=item * encoding

alg.

=item * key

The default value is I<server_key>.

=item * mode

# Describe

=item * string

The string to be decrypt can either be supplied first, creating an odd
number of arguments, or as a named parameter.

=back


=item process_key( $key, %params )

The following arguments may be specified:

=over 4

=item * literal_key

This disables mungung.

=item * key_size

Can be used to force a key size, even if the cipher specifies another size.

=item * cipher

Used to determine the key size.

=back


=item cipher_object( %params )

Available parameters are:

=over 4

=item * cipher

# Description.

=item * mode

# Description.

=back

Return an object using L<Crypt::CBC>.

=item digest_string( [ $string ], %params )

The following arguments are available:

=over 4

=item * digest

alg.

=item * string

The string to be digested can either be supplied first, creating an odd
number of arguments, or as a named parameter.

=back


=item verify_digest( %params )

The following parameters are accepted:

=over 4

=item * hash

A string containing the hash to verify.

=item * string

The digested string.

=item * fatal

If true, errors will be fatal.  The default is false, which means that
failures will return undef.

=back

In addition, the parameters which can be supplied to C<digest_string()>
may also be supplied to this method.

=item digest_object( %params )

params: digest

Returns an object using L<Digest>.

=item encode_string( [ $string ], %params )

=item decode_string( [ $string ], %params )

The following parameters are accepted:

=over 4

=item * encoding

The encoding may be a symbolic type (uri, printable) or a concrete type
(none, hex, base64, base32).

=back

=item mac_digest_string( [ $string ], %param )

=item verify_mac( %params )

XXX emac, hmac, etc wrapper?

The following arguments are allowed:

=over 4

=item * mac

The MAC string to verify.

=item * string

The digested string.

=item * type

One of 'digest' or 'cipher' (hmac or cmac).

=item * fatal

If true, errors will be fatal.  The default is false, which means that
failures will return undef.

=back

=item hmac_digest_string( %params )

=item verify_hmac( %params )

The following arguments are allowed:

=over 4

=item * mac

The MAC string to verify.

=item * string

The digested string.

=item * fatal

If true, errors will be fatal.  The default is false, which means that
failures will return undef.

=back

In addition, all the parameters which can be supplied to C<hmac_digest_string()>
are also available to this method.

=item cmac_digest_string( %params )

=item verify_cmac()

cmac, emac

with odd args the firstr is treated as the string

=item weak_random_string( %params )

A fairly entropic random string, suitable for digesting.

The result is the concatenation of several pseudorandom numbers.

This is a good enough value for e.g. session IDs.

The following parameters are available:

=over 4

=item * digest

Expects bool or algorithm. Unless disabled, the string will be digested with the default algorithm.

=item * encode

Expects bool or alg.

=back


=item strong_random_string( %params )

Available arguments are:

=over 4

=item * digest

Expects bool or alg.  The default is false.

=item * encode

Expects bool or alg.

=item * bytes

Expects a number; the default is 32.

=back


might not be supported (tries /dev/random  and/or the OpenSSL bindings)

=item encode_string_alphanumerical( $string )

=item decode_string_alphanumerical( $string )

=item encode_string_uri( $string )

=item decode_string_uri( $string )

encoding into a URI safe string

=item encode_string_printable( $string )

=item decode_string_printable( $string )

=item encode_string_hex( $string )

=item decode_string_hex( $string )

=item encode_string_uri_escape( $string )

=item decode_string_uri_escape( $string )

=item encode_string_base64( $string )

=item decode_string_base64( $string )

=item encode_string_base32( $string )

=item decode_string_base32( $string )

# "default" is there to be overridden by configs, if it returns nothing fallback will be called
# "fallback" is for when nothing is configured -- the class's default

=item disable_fallback()

When true only the first item from the fallback list will be tried, and if it
can't be loaded there will be a fatal error.

Enable this to ensure portability.

=item default_key()

=item default_cipher()

=item fallback_cipher()

find the first from fallback_cipher_list

=item fallback_cipher_list()

qw/Rijndael Serpent Twofish Blowfish RC6 RC5/

=item default_digest()

=item fallback_digest()

=item fallback_digest_list()

qw/SHA-1 SHA-256 RIPEMD160 Whirlpool MD5 Haval256/

=item default_encoding()

=item fallback_encoding()

=item fallback_encoding_list()

"hex"

=item default_alphanumerical_encoding()

=item fallback_alphanumerical_encoding()

=item fallback_alphanumerical_encoding_list()

"base32", "hex"

=item default_uri_encoding()

=item fallback_uri_encoding()

=item fallback_uri_encoding_list()

"uri_base64" # XXX make this uri_escape?

=item default_printable_encoding()

=item fallback_printable_encoding()

"base64"

=back

=head1 SEE ALSO

L<Digest>, L<Crypt::CBC>, L<Crypt::CFB>,
Lhttp://en.wikipedia.org/wiki/Block_cipher_modes_of_operation>.

=head1 VERSION CONTROL

This module is maintained using Darcs. You can get the latest version from
L<http://nothingmuch.woobling.org/Crypt-Util/>, and use C<darcs send> to commit
changes.

=head1 AUTHORS

Yuval Kogman, E<lt>nothingmuch@woobling.orgE<gt>

=head1 COPYRIGHT & LICENSE

Copyright 2006 by Yuval Kogman E<lt>nothingmuch@woobling.orgE<gt>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

=cut
