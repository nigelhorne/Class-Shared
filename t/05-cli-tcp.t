use strict;
use warnings;

use Test::More;
use File::Spec ();
use File::Temp qw(tempdir);
use IO::Socket::INET;
use POSIX ();
use lib 't/lib';

# The admin commands have to sign their frames too, so check them against a
# token-protected TCP backend rather than the unix socket t/03-cli.t uses.

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
print {$token_fh} "cli-s3cret\n";
close $token_fh;

my $bad_token_file = File::Spec->catfile($dir, 'bad-token');
open(my $bad_token_fh, '>', $bad_token_file) or plan skip_all => "cannot write $bad_token_file: $!";
print {$bad_token_fh} "not-the-token\n";
close $bad_token_fh;

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

ok($ready, 'the token-protected TCP backend came up') or BAIL_OUT('no backend to test against');

my $cli = "$^X -Ilib -It/lib bin/class-shared";
my $where = "--host 127.0.0.1 --port $port --token-file $token_file";

# status.
my $status = `$cli status --class Shared::Counter $where 2>&1`;
is($?, 0, 'status exits successfully over TCP') or diag $status;
like($status, qr/Shared::Counter: pid $pid\b/, 'status names the backend we started');
like($status, qr/address: 127\.0\.0\.1:$port/, 'and the TCP address');
like($status, qr/0 object\(s\)/, 'with no objects, since status makes none');
like($status, qr/\d+ call\(s\)/, 'and its call counter');
like($status, qr/clients: \d+/, 'and its client count');

# The CLI signs its frames, so a secret it does not have gets it nowhere.
my $wrong = `$cli status --class Shared::Counter --host 127.0.0.1 --port $port --token-file $bad_token_file 2>&1`;
isnt($?, 0, 'status with the wrong token fails');
like($wrong, qr/failed authentication/, 'and says the frames did not authenticate');

my $unsigned = `$cli status --class Shared::Counter --host 127.0.0.1 --port $port 2>&1`;
isnt($?, 0, 'status with no token fails');
like($unsigned, qr/handshake failed/, 'and says the handshake came to nothing');

# A backend that survived two refusals still answers the real thing.
my $again = `$cli status --class Shared::Counter $where 2>&1`;
is($?, 0, 'status still works after the refusals') or diag $again;

# stop.
my $stopped = `$cli stop --class Shared::Counter $where 2>&1`;
is($?, 0, 'stop exits successfully over TCP') or diag $stopped;
like($stopped, qr/stopped Shared::Counter/, 'stop says what it stopped');

waitpid($pid, 0);
is($?, 0, 'the backend we stopped exited cleanly');
undef $pid;

done_testing();
