use strict;
use warnings;

use Test::More;
use File::Spec ();
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);
use lib 't/lib';

use Class::Shared::Protocol;

my $message = {
	op     => 'call',
	method => 'do_something',
	args   => [1, [2, 3], { four => 5 }, undef, 'six'],
	want   => 'list',
};

my ($bytes, $encode_error) = Class::Shared::Protocol::encode_frame($message);
ok(defined $bytes, 'a message encodes');
is($encode_error, undef, 'no encoding error');

is(length($bytes), 4 + length($bytes) - 4, 'frame carries a header');
is(unpack('N', substr($bytes, 0, 4)), length($bytes) - 4, 'the header is the body length');

my ($decoded, $decode_error) = Class::Shared::Protocol::take_payload(substr($bytes, 4));
is($decode_error, undef, 'the body decodes');
is_deeply($decoded, $message, 'the message survives a round trip');

# Incremental parsing.
{
	my $buffer = $bytes;
	my @first = Class::Shared::Protocol::take_frame(\$buffer);
	is($first[0], 1, 'a whole frame in the buffer is taken');
	is_deeply($first[1], $message, 'and it is the right message');
	is($buffer, '', 'the buffer is empty afterwards');

	$buffer = substr($bytes, 0, 2);
	my @partial = Class::Shared::Protocol::take_frame(\$buffer);
	is($partial[0], 0, 'a partial header asks for more bytes');
	is($buffer, substr($bytes, 0, 2), 'and the partial header is kept');

	$buffer = substr($bytes, 0, 6);
	@partial = Class::Shared::Protocol::take_frame(\$buffer);
	is($partial[0], 0, 'a partial body asks for more bytes');
}

# Oversized frames are refused before anything is allocated.
{
	my $buffer = pack('N', $Class::Shared::Protocol::MAX_FRAME + 1) . 'x' x 8;
	my @huge = Class::Shared::Protocol::take_frame(\$buffer);
	is($huge[0], -1, 'an oversized frame is refused');
	like($huge[2], qr/exceeds the limit/, 'with an explanation');

	open(my $empty, '<', File::Spec->devnull) or plan skip_all => "cannot open $!";
	my (undef, $error) = Class::Shared::Protocol::read_frame($empty);
	like($error, qr/closed/, 'read_frame reports a stream with nothing to read');
}

# Real socket pair.
{
	socketpair(my $writer, my $reader, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
		or plan skip_all => "socketpair failed: $!";

	my ($written, $write_error) = Class::Shared::Protocol::write_all($writer, $bytes);
	ok($written, 'write_all writes the frame') or diag $write_error;

	my ($got, $read_error) = Class::Shared::Protocol::read_frame($reader);
	is($read_error, undef, 'read_frame reads it back');
	is_deeply($got, $message, 'over a real socket');
}

# A reply that cannot be serialised is reported, not fatal.
{
	my ($frame, $error) = Class::Shared::Protocol::encode_frame({ code => sub { 1 } });
	is($frame, undef, 'a code reference cannot be sent');
	like($error, qr/cannot serialise/, 'and the caller is told why');
}

done_testing();
