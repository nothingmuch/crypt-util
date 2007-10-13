#!/usr/bin/perl

package Crypt::Util;

use strict;
use warnings;

use base qw/Class::Accessor::Fast/;

our $VERSION = "0.05";

use Digest;
use Digest::MoreFallbacks;

use Perl6::Junction qw(any);

use Carp qw/croak/;

use Sub::Exporter;

BEGIN {
	our @DEFAULT_ACCESSORS = qw/
		mode
		authenticated_mode
		encode
		encoding
		digest
		cipher
		mac
		key
		uri_encoding
		printable_encoding
		use_literal_key
		tamper_proof_unencrypted
		tamper_proof_authenticated_mode
	/;

	__PACKAGE__->mk_accessors( map { "default_$_" } @DEFAULT_ACCESSORS );

	__PACKAGE__->mk_accessors("disable_fallback");

	my %export_groups = (
		'crypt' => [qw/
			encrypt_string decrypt_string
			authenticated_encrypt_string
			tamper_proof thaw_tamper_proof
			cipher_object
		/],
		digest => [qw/
			digest_string verify_hash verify_digest
			digest_object
			mac_digest_string
			verify_mac
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

our @KNOWN_AUTHENTICATING_MODES = qw(EAX OCB GCM CWC CCM),

our %FALLBACK_LISTS = (
	mode                    => [qw/CFB CBC Ctr OFB/],
	stream_mode             => [qw/CFB Ctr OFB/],
	block_mode              => [qw/CBC/],
	authenticated_mode      => [qw/EAX/], # OCB/], OCB is patented
	cipher                  => [qw/Rijndael Serpent Twofish RC6 Blowfish RC5/],
	digest                  => [qw/SHA-1 SHA-256 RIPEMD160 Whirlpool MD5 Haval256/],
	mac                     => [qw/HMAC CMAC/],
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

	my $e = do {
		local $@;
		eval { $self->digest_object( digest => $name ) };
		$@;
	};

	return 1 if !$e;
	( my $file = $name ) =~ s{::}{/}g;
	die $e if $e !~ m{^Can't locate Digest/\Q${file}.pm\E in \@INC};
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

	my $e = do {
		local $@;
		eval { require $file }; # yes it's portable
		$@;
	};

	return 1 if !$e;
	die $e if $e !~ /^Can't locate \Q$file\E in \@INC/;
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

		my $e = do {
			local $@;
			eval { require $module }; # yes it's portable
			$@;
		};

		return 1 if !$e;
		die $e if $e !~ /^Can't locate \Q$module\E in \@INC/;
		return;
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

	croak "mode $params{mode} is unsupported" unless $self->can($method);

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
[% FOR mode IN ["stream", "block", "authenticated"] %]
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

{
	# this is a hack that gives to Digest::HMAC something that responds to ->new

	package
	Crypt::Util::HMACDigestFactory;

	sub new {
		my $self = shift;
		$$self->clone;
	}

	sub new_factory {
		my ( $self, $thing ) = @_;
		return bless \$thing, $self;
	}
}

sub mac_object {
	my ( $self, %params ) = _args @_;

	$self->_process_params( \%params, qw/
		mac
	/);

	my $mac_type = delete $params{mac};

	my $method = lc( "mac_object_$mac_type" );

	$self->$method( %params );
}

sub mac_object_hmac {
	my ( $self, @args ) = _args @_;

	my $digest = $self->digest_object(@args);

	my $digest_factory = Crypt::Util::HMACDigestFactory->new_factory( $digest );

	my $key = $self->process_key(
		literal_key => 1, # Digest::HMAC does it's own key processing, but we let the user force our own
		key_size => 64,   # if the user did force our own, the default key_size is Digest::HMAC's default block size
		@args,
	);

	require Digest::HMAC;
	Digest::HMAC->new(
		$key,
		$digest_factory,
		# FIXME hmac_block_size param?
	);
}

use tt;
[% FOR f IN ["en", "de"] %]
sub [% f %]crypt_string {
	my ( $self, %params ) = _args @_, "string";

	my $string = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $string;

	my $c = $self->cipher_object( %params );

	[% IF f == "en" %]
	$self->maybe_encode( $c->encrypt($string), \%params );
	[% ELSE %]
	$c->decrypt( $self->maybe_decode($string, \%params ) );
	[% END %]
}

sub maybe_[% f %]code {
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

sub _digest_string_with_object {
	my ( $self, $object, %params ) = @_;

	my $string = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $string;

	$object->add($string);

	$self->maybe_encode( $object->digest, \%params );
}

sub digest_string {
	my ( $self, %params ) = _args @_, "string";

	my $d = $self->digest_object( %params );

	$self->_digest_string_with_object( $d, %params );
}

sub mac_digest_string {
	my ( $self, %params ) = _args @_, "string";

	my $d = $self->mac_object( %params );

	$self->_digest_string_with_object( $d, %params );
}

sub _do_verify_hash {
	my ( $self, %params ) = _args @_;

	my $hash = delete $params{hash};
	my $fatal = delete $params{fatal};
	croak "You must provide the 'string' and 'hash' parameters" unless defined $params{string} and defined $hash;

	my $meth = $params{digest_method};

	return 1 if $hash eq $self->$meth(%params);

	if ( $fatal ) {
		croak "Digest verification failed";
	} else {
		return;
	}
}

sub verify_hash {
	my ( $self, @args ) = @_;
	$self->_do_verify_hash(@args, digest_method => "digest_string");
}

sub verify_digest {
	my ( $self, @args ) = @_;
	$self->verify_hash(@args);
}

sub verify_mac {
	my ( $self, @args ) = @_;
	$self->_do_verify_hash(@args, digest_method => "mac_digest_string");
}

{
	my @flags = qw/serialized/;

	sub _flag_hash_to_int {
		my ( $self, $flags ) = @_;

		my $bit = 1;
		my $flags_int = 0;

		foreach my $flag (@flags) {
			$flags_int |= $bit if $flags->{$flag};
		} continue {
			$bit *= 2;
		}

		return $flags_int;
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
}

sub tamper_proof {
	my ( $self, %params ) = _args @_, "data";

	my $packed = $self->pack_data( %params );

	$self->tamper_proof_string( %params, string => $packed );
}

sub freeze_data {
	my ( $self, %params ) = @_;
	require Storable;
	Storable::nfreeze($params{data});
}

sub thaw_data {
	my ( $self, %params ) = @_;
	require Storable;
	Storable::thaw($params{data});
}

sub tamper_proof_string {
	my ( $self, %params ) = _args @_, "string";

	my $encrypted = exists $params{encrypt}
		? $params{encrypt}
		: !$self->default_tamper_proof_unencrypted;

	if ( $encrypted ) {
		if ( $self->_authenticated_mode(\%params) ) {
			return $self->_pack_tamper_proof( aead => $self->authenticated_encrypt_string(%params) );
		} else {
			croak "To use encrypted tamper resistent strings an authenticated encryption mode such as EAX must be selected";
		}
	} else {
		my $signed = $self->mac_tamper_proof_string( %params );
		$self->_pack_tamper_proof( mac => $signed );
	}
}

{
	my @tamper_proof_types = qw/mac aead/;
	my %tamper_proof_type; @tamper_proof_type{@tamper_proof_types} = 1 .. @tamper_proof_types;

	sub _pack_tamper_proof {
		my ( $self, $type, $proof ) = @_;
		pack("C a*", $tamper_proof_type{$type}, $proof);
	}

	sub _unpack_tamper_proof {
		my ( $self, $packed ) = @_;
		my ( $type, $string ) = unpack("C a*", $packed);

		return (
			($tamper_proof_types[ $type-1 ] || croak "Unknown tamper proofing method"),
			$string,
		);
	}
}

sub _authenticated_mode {
	my ( $self, $params ) = @_;

	# trust explicit param
	if ( exists $params->{authenticated_mode} ) {
		$params->{mode} = delete $params->{authenticated_mode};
		return 1;
	}

	# check if the explicit param is authenticated
	if ( exists $params->{mode} ) {
		# allow overriding
		if ( exists $params->{mode_is_authenticated} ) {
			return $params->{mode_is_authenticated};
		}

		if ( any( map { lc } @KNOWN_AUTHENTICATING_MODES ) eq lc($params->{mode}) ) {
			return 1;
		} else {
			return;
		}
	}

	$self->_process_params( $params, qw(authenticated_mode) );
	$params->{mode} = delete $params->{authenticated_mode};

	return 1;
}

sub _pack_hash_and_message {
	my ( $self, $hash, $message ) = @_;
	pack("n/a* a*", $hash, $message);
}

sub _unpack_hash_and_message {
	my ( $self, $packed ) = @_;
	unpack("n/a* a*", $packed);
}

our $PACK_FORMAT_VERSION = 1;

sub pack_data {
	my ( $self, %params ) = _args @_, "data";

	$self->_process_params( \%params, qw/
		data
	/);

	my $data = delete $params{data};

	my %flags;

	if ( ref $data ) {
		$flags{serialized} = 1;
		$data = $self->freeze_data( %params, data => $data );
	}

	$self->_pack_version_flags_and_string( $PACK_FORMAT_VERSION, \%flags, $data );
}

sub unpack_data {
	my ( $self, %params ) = _args @_, "data";

	$self->_process_params( \%params, qw/
		data
	/);

	my ( $version, $flags, $data ) = $self->_unpack_version_flags_and_string($params{data});

	$self->_packed_string_version_check( $version );

	if ( $flags->{serialized} ) {
		return $self->thaw_data( %params, data => $data );
	} else {
		return $data;
	}
}

sub _pack_version_flags_and_string {
	my ( $self, $version, $flags, $string ) = @_;
	pack("n n N/a*", $version, $self->_flag_hash_to_int($flags), $string);
}

sub _unpack_version_flags_and_string {
	my ( $self, $packed ) = @_;

	my ( $version, $flags, $string ) = unpack("n n N/a*", $packed);

	$flags = $self->_flag_int_to_hash($flags);

	return ( $version, $flags, $string );
}

sub authenticated_encrypt_string {
	my ( $self, %params ) = _args @_, "string";

	$self->_process_params( \%params, qw/
		authenticated_mode
	/);

	my $mac_type = delete $params{mac};
	return $self->encrypt_string( %params,  );
}

sub encrypt_and_digest_tamper_proof_string {
	my ( $self, %params ) = _args @_, "string";

	my $string = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $string;

	my $hash = $self->digest_string(
		%params,
		encode => 0,
		string => $string,
	);

	return $self->encrypt_string(
		%params,
		string => $self->_pack_hash_and_message( $hash, $string ),
	);
}

sub mac_tamper_proof_string {
	my ( $self, %params ) = _args @_, "string";

	my $string = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $string;

	my $hash = $self->mac_digest_string(
		%params,
		encode => 0,
		string => $string,
	);

	return $self->_pack_hash_and_message( $hash, $string );
}

sub thaw_tamper_proof {
	my ( $self, %params ) = _args @_, "string";

	my $string = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $string;

	my ( $type, $message ) = $self->_unpack_tamper_proof($string);

	my $method = "thaw_tamper_proof_string_$type";

	my $packed = $self->$method( %params, string => $message );
	$self->unpack_data(%params, data => $packed);
}

sub thaw_tamper_proof_string_encrypted {
	my ( $self, %params ) = _args @_, "string";

	my $hashed_packed = $self->decrypt_string( %params );

	my ( $hash, $packed ) = $self->_unpack_hash_and_message( $hashed_packed );

	return unless $self->verify_hash(
		fatal  => 1,
		%params, # allow user to override fatal
		hash   => $hash,
		decode => 0,
		string => $packed,
	);

	return $packed;
}

sub thaw_tamper_proof_string_mac {
	my ( $self, %params ) = _args @_, "string";

	my $hashed_packed = delete $params{string};
	croak "You must provide the 'string' parameter" unless defined $hashed_packed;

	my ( $hash, $packed ) = $self->_unpack_hash_and_message( $hashed_packed );

	return unless $self->verify_mac(
		fatal  => 1,
		%params,
		hash   => $hash,
		decode => 0,
		string => $packed,
	);

	return $packed;
}

sub _packed_string_version_check {
	my ( $self, $version ) = @_;

	croak "Incompatible packed string (I'm version $PACK_FORMAT_VERSION, thawing version $version)"
		unless $version == $PACK_FORMAT_VERSION;
}

use tt;
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
	my $tamper_resistent_string = $util->tamper_proof( $data );

	my $verified = $util->thaw_tamper_proof( $untrusted_string, key => "another secret" );

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

=head1 EXPORTED API

B<NOTE>: nothing is exported by default.

L<Crypt::Util> also presents an optional exported api using L<Sub::Exporter>.

Unlike typical exported APIs, there is no class level default instance shared
by all the importers, but instead every importer gets its own instance.

For example:

    package A;
    use Crypt::Util qw/:all/;

    default_key("moose");
    my $ciphertext = encrypt_string($plain);


    package B;
    use Crypt::Util qw/:all/;

    default_key("elk");
    my $ciphertext = encrypt_string($plain);

In this example every importing package has its own implicit instance, and the
C<default_key> function will in fact not share the value.

You can get the instance using the C<exported_instance> function, which is just
the identity method.

The export tags supported are: C<crypt> (encryption and tamper proofing related
functions), C<digest> (digest and MAC related functions), C<encoding> (various
encoding and decoding functions), and C<params> which give you functions for
handling default values.

=head1 METHODS

=over 4

=item tamper_proof( [ $data ], %params )

=item thaw_tamper_proof( [ $string ], %params )

=item tamper_proof_string $string, %params

=item thaw_tamper_proof_string $string, %params

The C<tamper_proof> method is in an intermittent state, in that the C<data>
parameter's API is not completely finalized.

It is safer to use C<tamper_proof_string>; its API is expected to remain the
same in future versions as well.

See L</TODO> for more information about the data types that will be supported
in the future.

When thawing, the C<verify_digest> or C<verify_mac> methods will be used, with
C<fatal> defaulting to on unless explicitly disabled in the parameters.

=over 4

This method accepts the following parameters:

=item * encrypt

By default this parameter is true, unless C<default_tamper_proof_unencrypted()>,
has been enabled.

A true value implies that all the parameters
which are available to C<encrypt_string()> are also available.  If a
negative value is specified, MAC mode is used, and the additional
parameters of C<mac_digest_string()> may also be specified to this method.

=item * data

The data to encrypt. If this is a reference L<Storable> will be used to
serialize the data.

=back

If the string is encrypted then all the parameters of C<encrypt_string> and
C<digest_string> are also available.

If the string is not encrypted, then all the parameters of C<mac_digest_string>
are also available.

=item encrypt_string( [ $string ], %params )

=item decrypt_string( [ $string ], %params )

All of the parameters which may be supplied to C<process_key()>,
C<cipher_object> and C<maybe_encode> are also available to these methods.

The following parameters may be used:

=over 4

=item * string

The string to be en/decrypted can either be supplied first, creating an odd
number of arguments, or as a named parameter.

=back

=item process_key( $key, %params )

The following arguments may be specified:

=over 4

=item * literal_key

This disables mungung. See also C<default_use_literal_key>.

=item * key_size

Can be used to force a key size, even if the cipher specifies another size.

If not specified, the key size chosen will depend 

=item * cipher

Used to determine the key size.

=back

=item cipher_object( %params )

Available parameters are:

=over 4

=item * cipher

The cipher algorithm to use.

=item * mode

The mode of operation (C<cbc>, C<cfb>).

See L<http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation> for an
explanation of this.

=back

=item digest_string( [ $string ], %params )

Delegates to C<digest_object>. All parameters which can be used by
C<digest_object> may also be used here.

The following arguments are available:

=over 4

=item * string

The string to be digested can either be supplied first, creating an odd
number of arguments, or as a named parameter.

=back

=item verify_digest( %params )

Delegates to C<digest_object>. All parameters which can be used by
C<digest_object> may also be used here.

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

=over 4

=item * digest

The digest algorithm to use.

=back

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

Delegates to C<mac_object>. All parameters which can be used by C<mac_object>
may also be used here.

=over 4

=item * string

=back

=item verify_mac( %params )

Delegates to C<mac_object>. All parameters which can be used by C<mac_object>
may also be used here.

The following additional arguments are allowed:

=over 4

=item * hash

The MAC string to verify.

=item * string

The digested string.

=item * fatal

If true, errors will be fatal.  The default is false, which means that
failures will return undef.

=back

=item mac_object

=over 4

=item * mac

The MAC algorithm to use. Currently only C<hmac> is supported.

=back

=item maybe_encode

=item maybe_decode

This method has no external API but is documented for the sake of its shared
options.

It is delegated to by the various encryption and digest method.

=over 4

=item * encode

Expects a bool.

=item * encoding

Expects an algorithm name (symbolic (e.g. C<uri>, C<alphanumeric>), or concrete
(e.g. C<base64>, C<hex>)).

=back

If C<encode> is explicitly supplied it will always determine whether or not the
string will be encoded. Otherwise, if C<encoding> is explicitly supplied then
the string will always be encoded using the specified algorithm. If neither is
supplied C<default_encode> will be checked to determine whether or not to
encode, and C<default_encoding> or C<fallback_encoding> will be used to
determine the algorithm to use (see L</HANDLING OF DEFAULT VALUES>).

=item encode_string_alphanumerical( $string )

=item decode_string_alphanumerical( $string )

=item encode_string_uri( $string )

=item decode_string_uri( $string )

=item encode_string_printable( $string )

=item decode_string_printable( $string )

The above methods encode based on a fallback list (see L</HANDLING OF DEFAULT VALUES>).

The variations denote types of formats: C<alphanumerical> is letters and
numbers only (case insensitive), C<uri> is safe for inclusions in URIs (without
further escaping), and C<printable> contains no control characters or
whitespace.

=item encode_string_hex( $string )

=item decode_string_hex( $string )

Big endian hexadecimal (C<H*> pack format).

=item encode_string_uri_escape( $string )

=item decode_string_uri_escape( $string )

L<URI::Escape> based encoding.

=item encode_string_base64( $string )

=item decode_string_base64( $string )

=item encode_string_base64_wrapped( $string )

Requires L<MIME::Base64>.

The C<wrapped> variant will introduce line breaks as per the L<MIME::Base64>
default>.

=item encode_string_uri_base64

=item decode_string_uri_base64

Requires L<MIME::Base64>.

Implements the Base64 for URIs. See
L<http://en.wikipedia.org/wiki/Base64#URL_Applications>.

=item encode_string_base32( $string )

=item decode_string_base32( $string )

Requires L<MIME::Base32>.

(note- unlike L<MIME::Base32> this is case insensitive).

=head1 HANDLING OF DEFAULT VALUES

=over 4

=item disable_fallback()

When true only the first item from the fallback list will be tried, and if it
can't be loaded there will be a fatal error.

Enable this to ensure portability.

=back

For every parameter, there are several methods, where PARAMETER is replaced
with the parameter name:

=over 4

=item * default_PARAMETER()

This accessor is available for the user to override the default value.

If set to undef, then C<fallback_PARAMETER> will be consulted instead.

B<ALL> the default values are set to undef unless changed by the user.

=item * fallback_PARAMETER()

Iterates the C<fallback_PARAMETER_list>, choosing the first value that is
usable (it's provider is available).

If C<disable_fallback> is set to a true value, then only the first value in the
fallback list will be tried.

=item * fallback_PARAMETER_list()

An ordered list of values to try and use as fallbacks.

C<fallback_PARAMETER> iterates this list and chooses the first one that works.

=back

Available parameters are as follows:

=over 4

=item * cipher

The fallback list is
C<Rijndael>, C<Serpent>, C<Twofish>, C<RC6>, C<Blowfish> and C<RC5>.

L<Crypt::Rijndael> is the AES winner, the next three are AES finalists, and the
last two are well known and widely used.

=item * mode

The mode in which to use the cipher.

The fallback list is C<CFB>, C<CBC>, C<Ctr>, and C<OFB>.

=item digest

The fallback list is C<SHA-1>, C<SHA-256>, C<RIPEMD160>,
C<Whirlpool>, C<MD5>, and C<Haval256>.

=item * encoding

The fallback list is C<hex> (effectively no fallback).

=item alphanumerical_encoding

The fallback list is C<base32> and C<hex>.

L<MIME::Base32> is required for C<base32> encoding.

=item * uri_encoding

The fallback list is C<uri_base64>.

=item * printable_encoding

The fallback list is C<base64>

=back

=head2 Defaults with no fallbacks

The following parameters have a C<default_> method, as described in the
previous section, but the C<fallback_> methods are not applicable.

=over 4

=item * encode

Whether or not to encode by default (applies to digests and encryptions).

=item * key

The key to use. Useful for when you are repeatedly encrypting.

=item * use_literal_key

Whether or not to not hash the key by default. See C<process_key>.

=item * tamper_proof_unencrypted

Whether or not tamper resistent strings are by default unencrypted (just MAC).

=back

=head2 Subclassing

You may safely subclass and override C<default_PARAMETER> and
C<fallback_PARAMETER_list> to provide values from configurations.

Overriding the C<fallback_PARAMETER> method is also "allowed" but not
reccomended.

=back

=head1 TODO

Features which are currently missing but are scheduled for 0.02 or 0.03:

=over 4

=item *

Crypt::SaltedHash support

=item *

=item *

CMAC, EMAC (maybe, the modules are not OO and require refactoring) message
authentication modes.

=item *

EAX/OCB encryption mode (with implicit authentication)

=item *

Bruce Schneier Fact Database
L<http://geekz.co.uk/lovesraymond/archive/bruce-schneier-facts>.

=item *

Entropy fetching (get N weak/strong bytes, etc) from e.g. OpenSSL bindings,
/dev/*random, and EGD.

=item *

Additional data formats (streams/iterators, filehandles, generalized storable
data/string handling for all methods, not just tamper_proof).

Streams should also be able to used via a simple push api.

=head1 SEE ALSO

L<Digest>, L<Crypt::CBC>, L<Crypt::CFB>,
L<http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation>.

=head1 VERSION CONTROL

This module is maintained using Darcs. You can get the latest version from
L<http://nothingmuch.woobling.org/Crypt-Util/>, and use C<darcs send> to commit
changes.

=head1 AUTHORS

Yuval Kogman, E<lt>nothingmuch@woobling.orgE<gt>
Ann Barcomb

=head1 COPYRIGHT & LICENSE

Copyright 2006 by Yuval Kogman E<lt>nothingmuch@woobling.orgE<gt>, Ann Barcomb

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
