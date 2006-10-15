#!/usr/bin/perl

package Crypt::Util;

use strict;
use warnings;

use base qw/Class::Accessor::Fast/;

use Digest;
use Crypt::CBC;
use Storable;

use Carp qw/croak/;

our @DEFAULT_ACCESSORS = qw/
	encoding
	digest
	cipher
	key
	default_uri_encoding
	default_printable_encoding
/;

__PACKAGE__->mk_accessors( map { "default_$_" } @DEFAULT_ACCESSORS );

__PACKAGE__->mk_accessors("disable_fallback");

our %FALLBACK_LISTS = (
	cipher => [qw/Rijndael Twofish Blowfish IDEA RC6 RC5/],
	digest => [qw/SHA1 SHA256 RIPEMD160 Whirlpool MD5/],
	alpha_alphanumerical_encoding => [qw/base32 hex/],
);

foreach my $fallback ( keys %FALLBACK_LISTS ) {
	my @list = @{ $FALLBACK_LISTS{$fallback} };

	my $list_method = "fallback_${fallback}_list";

	constant->import( $list_method => @list );

	my $fallback_sub = sub {
		my $self = shift;

		$self->_find_fallback(
			$fallback,
			"_try_${fallback}_fallback",
			$self->$list_method,
		) || croak "Couldn't load any $fallback";
	};

	no strict 'refs';
	*{ "fallback_$fallback" } = $fallback_sub;
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
	eval { $self->cipher_object( cipher => $name, key => "" ) };
	
	return 1 if !$@;
	die $@ if $@ !~ /^Couldn't load Crypt::$name/;
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
	my ( $self, %params ) = @_;
	
	$self->_process_params( \%params, qw/
		cipher
		key
	/);

	Crypt::CBC->new(
		-cipher => $params{cipher},
		-key    => $params{key},
	);
}

sub digest_object {
	my ( $self, %params ) = @_;

	$self->_process_params( \%params, qw/
		digest
	/);

	Digest->new( $params{digest} );
}

use tt;
[% FOR f IN ["en", "de"] %]
sub [% f %]crypt_string {
	my ( $self, %params ) = @_;

	my $string = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $string;

	my $c = $self->cipher_object( %params );

	[% IF f == "en" %]
	$self->_maybe_encode( $c->[% f %]crypt($string), \%params );
	[% ELSE %]
	$c->[% f %]crypt( $self->_maybe_decode($string), \%params );
	[% END %]
}

sub _maybe_[% f %]code {
	my ( $self, $string, $params ) = @_;

	if ( my $encoding = delete $params->{encoding} ) {
		$encoding = $self->_process_param("encoding")
			unless $encoding =~ /^[a-z]\w+$/i;

		return $self->[% f %]code(
			%$params,
			encoding => $encoding,
			string   => $string,
		);
	} else {
		return $string;
	}
}
[% END %]
no tt;

sub digest_string {
	my ( $self, %params ) = @_;

	my $string = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $string;

	my $d = $self->digest_object( %params );

	$d->add($string);

	$self->_maybe_encode( $d->digest, \%params );
}

sub verify_hash {
	my ( $self, %params ) = @_;

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
	my ( $self, %params ) = @_;

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
		encoding => 0,
		string   => $packed,
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
	my ( $self, %params ) = @_;

	my $hashed_packed = $self->decrypt_string( %params );

	my ( $hash, $version, $flags, $packed ) = unpack("n/a n n X[n n] a*", $hashed_packed);

	$self->_tamper_protect_version_check( $version );

	my %flags = $self->_flag_int_to_hash($flags);

	return unless $self->verify_hash(
		fatal    => 1,
		%params, # allow user to override fatal
		hash     => $hash,
		encoding => 0,
		string   => $packed,
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

	my $tamper_resistent_string = $util->encode_tamper_resistent( $data ); # can also take refs

	my $trusted = $util->decode_tamper_resistent( $untrusted_string, key => "another secret" );

	# without specifying which encoding returns base32 or hex if base32 is unavailable
	my $encoded = $util->encode_string( $bytes );

	my $hash = $util->digest( $bytes, digest => "md5" );

	die "baaaad" unless $util->verify_hash(
		hash => $hash,
		data => $bytes,
		digest => "md5",
	);

=head1 DESCRIPTION

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

=item encode_string_uri_escaping $string

=item decode_string_uri_escaping $string

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

"hex"

=item default_alphanumerical_encoding

=item fallback_alphanumerical_encoding

=item fallback_alphanumerical_encoding_list

"base32", "hex"

=item default_uri_encoding

=item fallback_printable_encoding

"alphanumerical" # XXX make this uri_escape?

=item default_printable_encoding

=item fallback_printable_encoding

"base64"

=back

=cut


