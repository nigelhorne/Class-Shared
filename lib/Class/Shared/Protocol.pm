package Class::Shared::Protocol;

use strict;
use warnings;

use Storable ();

our $VERSION = '0.01';

# Requests and responses are a 4 byte network order length followed by a
# Storable image of a hashref.  One frame in flight per connection.
our $MAX_FRAME = 64 * 1024 * 1024;

# When a shared secret is in use the payload is an HMAC-SHA-256 of the body
# followed by the body.  The digest is checked before Storable sees a byte, so
# a peer that does not know the secret cannot make this process thaw -- and so
# run -- code of its choosing.
our $DIGEST_SIZE = 32;

sub encode_frame {
	my ($message, $secret) = @_;

	my $frozen = eval { Storable::nfreeze($message) };
	if (!defined $frozen) {
		my $error = $@ || 'unknown error';
		$error =~ s/\s+\z//;
		return (undef, "cannot serialise message: $error");
	}

	if (length($frozen) > $MAX_FRAME) {
		return (undef, 'message is too large (' . length($frozen)
			. " bytes, limit is $MAX_FRAME)");
	}

	if (defined $secret) {
		my $digest = _digest($secret, $frozen);
		return pack('N', length($digest) + length($frozen)) . $digest . $frozen;
	}

	return pack('N', length($frozen)) . $frozen;
}

sub take_payload {
	my ($body) = @_;

	my $message = eval { Storable::thaw($body) };
	if ($@) {
		my $error = $@;
		$error =~ s/\s+\z//;
		return (undef, "cannot deserialise message: $error");
	}

	return ($message, undef);
}

# Write every byte, or report why not.
# Returns (1) on success, (0, $error) on failure.
sub write_all {
	my ($fh, $bytes) = @_;

	# A backend that has just died must not take the client with it.
	local $SIG{PIPE} = 'IGNORE';

	my $length = length $bytes;
	my $offset = 0;

	while ($offset < $length) {
		my $written = syswrite($fh, $bytes, $length - $offset, $offset);

		if (!defined $written) {
			return (0, "write failed: $!");
		}
		if ($written == 0) {
			return (0, 'write failed: peer closed the connection');
		}

		$offset += $written;
	}

	return (1);
}

# Blocking read of exactly one frame.  Returns ($message) or (undef, $error).
# An optional timeout is in seconds.
sub read_frame {
	my ($fh, $timeout, $secret) = @_;

	my ($header, $error) = _read_exact($fh, 4, $timeout);
	return (undef, $error) unless defined $header;

	my $length = unpack('N', $header);
	my $room = defined $secret ? $MAX_FRAME + $DIGEST_SIZE : $MAX_FRAME;

	return (undef, "frame of $length bytes exceeds the limit of $room")
		if $length > $room;

	my ($payload, $body_error) = _read_exact($fh, $length, $timeout);
	return (undef, $body_error) unless defined $payload;

	return _decode($payload, $secret);
}

sub _read_exact {
	my ($fh, $length, $timeout) = @_;

	my $buffer = '';

	while (length($buffer) < $length) {
		# A TLS socket can be holding decrypted bytes that select cannot
		# see, because they arrived in a record already read from the kernel.
		# Take those before waiting for more.
		if ($fh->can('pending') && $fh->pending) {
			my $pending = sysread($fh, $buffer, $length - length($buffer),
				length($buffer));

			return (undef, "read failed: $!") if !defined $pending;
			return (undef, 'connection closed by peer') if $pending == 0;

			next;
		}

		if (defined $timeout) {
			my $rin = '';
			vec($rin, fileno($fh), 1) = 1;
			my $ready = select(my $rout = $rin, undef, undef, $timeout);
			return (undef, 'timed out waiting for a reply')
				if !defined $ready || $ready <= 0;
		}

		my $got = sysread($fh, $buffer, $length - length($buffer), length($buffer));

		if (!defined $got) {
			return (undef, "read failed: $!");
		}
		if ($got == 0) {
			return (undef, 'connection closed by peer');
		}
	}

	return ($buffer);
}

# Incremental parser for the backend's select loop.  With a secret, a frame
# whose digest does not verify is reported as unusable without being thawed.
# Returns ( 1, $message, undef) when a whole frame was taken out of the buffer,
#         ( 0, undef,    undef) when more bytes are needed,
#         (-1, undef,    $error) when the stream is unusable.
sub take_frame {
	my ($buffer_ref, $secret) = @_;

	return (0, undef, undef) if length($$buffer_ref) < 4;

	my $length = unpack('N', substr($$buffer_ref, 0, 4));
	my $room = defined $secret ? $MAX_FRAME + $DIGEST_SIZE : $MAX_FRAME;

	return (-1, undef, "frame of $length bytes exceeds the limit of $room")
		if $length > $room;

	return (0, undef, undef) if length($$buffer_ref) < 4 + $length;

	my $payload = substr($$buffer_ref, 4, $length);
	substr($$buffer_ref, 0, 4 + $length) = '';

	my ($message, $error) = _decode($payload, $secret);
	return (-1, undef, $error) if defined $error;

	return (1, $message, undef);
}

# Payload to message.  With a secret the digest is checked first, and the body
# is not handed to Storable unless it matches: thaw() runs whatever the sender
# put in the image, so the authentication has to happen before it, not after.
sub _decode {
	my ($payload, $secret) = @_;

	my $body = $payload;

	if (defined $secret) {
		return (undef, 'frame is too short to be authenticated')
			if length($payload) < $DIGEST_SIZE;

		my $digest = substr($payload, 0, $DIGEST_SIZE);
		$body = substr($payload, $DIGEST_SIZE);

		return (undef, 'frame failed authentication')
			unless _authentic($secret, $body, $digest);
	}

	return take_payload($body);
}

# Loaded on demand: a client that only talks to a local unix socket without a
# token never pays to load Digest::SHA.
sub _digest {
	my ($secret, $body) = @_;

	require Digest::SHA;

	return Digest::SHA::hmac_sha256($body, $secret);
}

# Compared without an early exit, so that the time taken says nothing about
# how much of a guessed digest was right.
sub _authentic {
	my ($secret, $body, $digest) = @_;

	my $expected = _digest($secret, $body);

	return 0 unless length($expected) == length($digest);

	my $difference = 0;
	for my $offset (0 .. length($expected) - 1) {
		$difference |= ord(substr($expected, $offset, 1))
			^ ord(substr($digest, $offset, 1));
	}

	return $difference == 0 ? 1 : 0;
}

1;

__END__

=head1 NAME

Class::Shared::Protocol - framing for Class::Shared's socket protocol

=head1 SYNOPSIS

    my ($bytes, $error) = Class::Shared::Protocol::encode_frame({ op => 'ping' });
    Class::Shared::Protocol::write_all($socket, $bytes);

    my ($message, $read_error) = Class::Shared::Protocol::read_frame($socket);

    # With a shared secret, every frame is authenticated:
    my ($signed, $sign_error) = Class::Shared::Protocol::encode_frame({ op => 'ping' }, $secret);
    my ($reply, $reply_error) = Class::Shared::Protocol::read_frame($socket, undef, $secret);

=head1 DESCRIPTION

A frame is a four byte big endian length followed by a L<Storable> image of a
hash reference.  One request or response is in flight per connection.

When a shared secret is in use the payload is instead a 32 byte HMAC-SHA-256 of
the body followed by the body:

    length | hmac-sha256(secret, body) | storable image of the request

The digest is verified before the body is thawed.  That ordering is the point:
L<Storable::thaw> instantiates whatever the image describes, running the
sender's choice of code, so a frame from somebody who does not know the secret
must be rejected before it reaches Storable.

Nothing here knows what the messages mean; that lives in
L<Class::Shared::Backend>.

=head1 FUNCTIONS

=over 4

=item encode_frame($message, $secret)

Returns the framed bytes, or C<(undef, $error)> if the message cannot be
serialised or is larger than C<$Class::Shared::Protocol::MAX_FRAME>.  With a
C<$secret> the frame carries an HMAC-SHA-256 of its body.

=item write_all($filehandle, $bytes)

Writes every byte.  Returns C<(1)>, or C<(0, $error)>.

=item read_frame($filehandle, $timeout, $secret)

Reads one frame, waiting forever unless C<$timeout> (seconds) is given.
Returns C<($message)>, or C<(undef, $error)> on end of file, timeout, a frame
that fails authentication, or unusable data.

=item take_frame(\$buffer, $secret)

The non-blocking parser for the backend's select loop.  Takes one complete
frame out of the buffer and returns C<(1, $message, undef)>; returns
C<(0, undef, undef)> when more bytes are needed; returns C<(-1, undef,
$error)> if the stream cannot be parsed or a frame does not authenticate.  A
frame that fails authentication is discarded without being thawed.

=item take_payload($body)

Thaws a frame body, with no authentication.  Returns C<($message, undef)> or
C<(undef, $error)>.  Use C<take_frame> or C<read_frame> instead when the bytes
came from a network.

=back

=head1 NOTES

L<Storable::thaw> trusts its input: it instantiates classes and runs their
C<STORABLE_thaw> hooks, which is remote code execution for anyone who can
write to the socket.  Pass a secret and the digest is checked first.  A backend
with no secret -- the default for a unix socket -- still trusts whatever it is
sent, which is why the unix socket is mode 0600 in a directory only its owner
can write to; a TCP listener always has one.

=head1 SEE ALSO

L<Class::Shared::Frontend>, L<Class::Shared::Backend>.

=head1 AUTHOR

Nigel Horne

=head1 LICENSE

This module is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
