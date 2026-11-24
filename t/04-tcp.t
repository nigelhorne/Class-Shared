use strict;
use warnings;

use Test::More;
use File::Spec ();
use File::Temp qw(tempdir);
use IO::Socket::INET;
use POSIX ();
use lib 't/lib';

use Class::Shared::Frontend;

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
like($@, qr/bad or missing token/, 'and is told why');

my $wrong_token = eval {
	Class::Shared::Frontend->new(
		'Shared::Counter',
		host  => '127.0.0.1',
		port  => $port,
		token => 'not-the-token',
	);
};
ok(!defined $wrong_token, 'a client with the wrong token gets no object');
like($@, qr/bad or missing token/, 'and is told why');

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
