use strict;
use warnings;

use Test::More;
use File::Spec ();
use File::Temp qw(tempdir);
use IO::Socket::INET;
use POSIX ();
use lib 't/lib';

use Class::Shared ();
use Class::Shared::Frontend;
use Class::Shared::Protocol;

my $dir = tempdir(CLEANUP => 1);

# Take a free port by opening one and letting it go again.
my $probe = IO::Socket::INET->new(
	LocalAddr => '127.0.0.1',
	LocalPort => 0,
	Proto     => 'tcp',
	Listen    => 1,
	ReuseAddr => 1,
) or plan skip_all => "cannot open a listening TCP socket: $!";

my $port = $probe->sockport;
close $probe;

my $token_file = File::Spec->catfile($dir, 'token');
open(my $token_fh, '>', $token_file) or plan skip_all => "cannot write $token_file: $!";
print {$token_fh} "s3cret-token\n";
close $token_fh;

# A port anybody can route to must not be a port where a stranger's bytes reach
# Storable::thaw, so a TCP listener without a token refuses to start at all.
my $tokenless = `$^X -Ilib -It/lib bin/class-shared serve --class Shared::Counter --listen tcp:127.0.0.1:$port -f 2>&1`;
isnt($?, 0, 'a TCP listener with no token refuses to start');
like($tokenless, qr/needs a token/, 'and says that a token is required');

my $still_closed = IO::Socket::INET->new(
	PeerAddr => '127.0.0.1',
	PeerPort => $port,
	Proto    => 'tcp',
	Timeout  => 1,
);
ok(!$still_closed, 'and left nothing listening on the port');
close $still_closed if $still_closed;

my $pid = fork;
if (!defined $pid) {
	plan skip_all => "cannot fork: $!";
}

if ($pid == 0) {
	no warnings 'exec';    # exec() does not return when it works
	exec(
		$^X, '-Ilib', '-It/lib', 'bin/class-shared', 'serve',
		'--class', 'Shared::Counter',
		'--listen', "tcp:127.0.0.1:$port",
		'--token-file', $token_file,
		'--dir', $dir,
		'-f',
	);
	POSIX::_exit(127);
}

END {
	kill 'TERM', $pid if $pid && kill(0, $pid);
}

my $ready = 0;
for (1 .. 200) {
	my $probe_socket = IO::Socket::INET->new(
		PeerAddr => '127.0.0.1',
		PeerPort => $port,
		Proto    => 'tcp',
		Timeout  => 1,
	);
	if ($probe_socket) {
		close $probe_socket;
		$ready = 1;
		last;
	}
	select(undef, undef, undef, 0.05);
}

ok($ready, 'the TCP backend came up') or BAIL_OUT('no backend to test against');

my $frontend = Class::Shared::Frontend->new(
	'Shared::Counter',
	host       => '127.0.0.1',
	port       => $port,
	token_file => $token_file,
	ctor       => [start => 5],
);

is($frontend->shared_pid, $pid, 'the frontend talks to the backend we started');
is($frontend->shared_address, "127.0.0.1:$port", 'it knows the address');
is($frontend->value, 5, 'the object was constructed in the backend');
is($frontend->inc, 6, 'a call works over TCP');

my $second = Class::Shared::Frontend->new(
	'Shared::Counter',
	host       => '127.0.0.1',
	port       => $port,
	token_file => $token_file,
	ctor       => [start => 1],
);

isnt($second->shared_id, $frontend->shared_id, 'a second client gets its own object');
is($second->value, 1, 'with its own state');
is($frontend->value, 6, 'and neither disturbs the other');
is($second->shared_pid, $frontend->shared_pid, 'both objects share the one backend');

# Authentication.
my $no_token = eval {
	Class::Shared::Frontend->new('Shared::Counter', host => '127.0.0.1', port => $port);
};
ok(!defined $no_token, 'a client without the token gets no object');
like($@, qr/may require a token|failed authentication/, 'and is told why');

my $wrong_token = eval {
	Class::Shared::Frontend->new(
		'Shared::Counter',
		host  => '127.0.0.1',
		port  => $port,
		token => 'not-the-token',
	);
};
ok(!defined $wrong_token, 'a client with the wrong token gets no object');
like($@, qr/failed authentication/, 'and is told that its frames do not authenticate');

# A frame this backend cannot authenticate must be refused before it is thawed.
# The bodies below are valid Storable images, so the digest is the only thing
# between them and the backend's interpreter.
my @forged = (
	[
		'signed with the wrong secret',
		(Class::Shared::Protocol::encode_frame({
			op    => 'hello',
			proto => $Class::Shared::PROTOCOL_VERSION,
			class => 'Shared::Counter',
			token => 'not-the-token',
		}, 'not-the-token'))[0],
	],
	[
		'with no digest at all',
		(Class::Shared::Protocol::encode_frame({
			op    => 'hello',
			proto => $Class::Shared::PROTOCOL_VERSION,
			class => 'Shared::Counter',
			token => 's3cret-token',
		}))[0],
	],
);

for my $case (@forged) {
	my ($label, $frame) = @{$case};

	ok(defined $frame, "a frame $label is built") or next;

	my $raw = IO::Socket::INET->new(
		PeerAddr => '127.0.0.1',
		PeerPort => $port,
		Proto    => 'tcp',
		Timeout  => 5,
	) or BAIL_OUT("cannot open a raw connection to the backend: $!");

	my ($sent) = Class::Shared::Protocol::write_all($raw, $frame);
	ok($sent, 'and sent to the backend');

	my ($reply, $read_error) = Class::Shared::Protocol::read_frame($raw, 5, 's3cret-token');
	ok(defined $reply, 'the backend answers') or diag $read_error;
	next unless $reply;

	ok(!$reply->{ok}, "the frame $label is refused");
	like($reply->{error}, qr/failed authentication|too short/,
		'because it could not be authenticated');

	# The connection is dropped rather than kept for another guess.
	my ($after, $after_error) = Class::Shared::Protocol::read_frame($raw, 5, 's3cret-token');
	is($after, undef, 'and the connection is closed');
	like($after_error, qr/closed/, 'as a closed stream');

	close $raw;
}

is($frontend->value, 6, 'the real client still works after the forgeries');

# Nothing can be autostarted over TCP: a closed port is an error.
my $closed = IO::Socket::INET->new(
	LocalAddr => '127.0.0.1',
	LocalPort => 0,
	Proto     => 'tcp',
	Listen    => 1,
	ReuseAddr => 1,
);
my $closed_port = $closed->sockport;
close $closed;

eval {
	Class::Shared::Frontend->new(
		'Shared::Counter',
		host  => '127.0.0.1',
		port  => $closed_port,
		token => 's3cret-token',
	);
};
like($@, qr/cannot reach a backend/, 'a closed TCP endpoint is an error, not a spawn');

ok($frontend->shared_shutdown, 'the TCP backend can be stopped');
waitpid($pid, 0);
is($?, 0, 'and it exited cleanly');

done_testing();
