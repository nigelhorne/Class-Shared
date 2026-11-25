use strict;
use warnings;

use Test::More;

# t/04 covers the reply queue over TLS.  The unix socket takes a different path
# into the same code -- it is made non-blocking in _accept rather than in
# _start_tls -- so it gets the same tests.  Three cases, because a reply over
# the bound is refused before anything is written, a reply within it is written
# in part and the rest queued, and a queued reply that never moves is on a
# deadline:
#
#   1. more than max_queued, never read: another client is served, the connection
#      is dropped, and its object goes with it;
#   2. within max_queued but larger than the socket buffer, not read at once: the
#      loop serves another client meanwhile, and the whole reply arrives intact
#      when the client finally reads it;
#   3. within max_queued and never read: the connection is dropped once the
#      queue has made no progress for write_timeout, and its object goes with it.
BEGIN {
	plan skip_all => 'this uses a unix socket in an owner-only directory, '
		. "which MSWin32 does not have"
		if $^O eq 'MSWin32';
}

use File::Spec ();
use File::Temp qw(tempdir);
use IO::Socket::UNIX;
use POSIX ();
use Socket qw(SOCK_STREAM);
use Time::HiRes ();
use lib 't/lib';

use Class::Shared ();
use Class::Shared::Backend ();
use Class::Shared::Protocol ();

my $dir = tempdir(CLEANUP => 1);
my $limit = 8 * 1024 * 1024;

my @backends;

sub start_backend {
	my ($where, $log, %option) = @_;

	my $pid = fork;
	BAIL_OUT("cannot fork: $!") unless defined $pid;

	if (!$pid) {
		my $ok = eval {
			Class::Shared::Backend->new(
				dir        => $where,
				max_queued => $limit,
				log        => $log,
				daemonize  => 0,
				%option,
			)->run;

			1;
		};

		# _exit, so Test::More's END block does not run in the child.
		POSIX::_exit($ok ? 0 : 1);
	}

	push @backends, $pid;

	return $pid;
}

END {
	kill 'TERM', $_ for grep { $_ && kill(0, $_) } @backends;
}

my $log = "$dir/backend.log";
my $pid = start_backend($dir, $log);

sub connect_unix {
	my ($path) = @_;

	return IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $path);
}

sub send_frame {
	my ($sock, $message) = @_;

	my ($bytes) = Class::Shared::Protocol::encode_frame($message);
	return 0 unless defined $bytes;

	my ($written) = Class::Shared::Protocol::write_all($sock, $bytes);

	return $written ? 1 : 0;
}

sub ask {
	my ($sock, $message) = @_;

	return unless send_frame($sock, $message);

	my ($reply) = Class::Shared::Protocol::read_frame($sock, 5);

	return $reply;
}

sub new_connection {
	my ($path, $class) = @_;

	my $sock = connect_unix($path);
	return unless $sock;

	my $hello = ask($sock, {
		op    => 'hello',
		proto => $Class::Shared::PROTOCOL_VERSION,
		class => $class,
	});

	if (!$hello || !$hello->{ok}) {
		close $sock;
		return;
	}

	my $object = ask($sock, { op => 'new', args => [] });

	if (!$object || !$object->{ok}) {
		close $sock;
		return;
	}

	return ($sock, $object->{id});
}

sub slurp {
	my ($path) = @_;

	open(my $fh, '<', $path) or return '';
	my $text = do { local $/; <$fh> };
	close $fh;

	return defined $text ? $text : '';
}

# The CLI, with a deadline: a backend wedged on a write must fail the test
# rather than leave the suite waiting on a reply that will never come.
sub run_cli {
	my ($where, @args) = @_;

	my ($output, $status) = ('', 0);

	my $answered = eval {
		local $SIG{ALRM} = sub { die "timed out\n" };

		alarm 10;
		$output = `$^X -Ilib -It/lib bin/class-shared @args --dir $where 2>&1`;
		$status = $? >> 8;
		alarm 0;

		1;
	};

	BAIL_OUT("class-shared @args did not answer: " . ($@ || 'unknown error'))
		unless $answered;

	return ($output, $status);
}

sub objects_held {
	my ($where) = @_;

	my ($output) = run_cli($where, 'status');

	my ($objects) = $output =~ /(\d+) object\(s\)/;

	BAIL_OUT("cannot read an object count from: $output") unless defined $objects;

	return $objects;
}

sub read_until_closed {
	my ($sock) = @_;

	my $give_up = Time::HiRes::time() + 5;
	while (Time::HiRes::time() < $give_up) {
		my $rin = '';
		vec($rin, fileno($sock), 1) = 1;
		return 0 unless select(my $rout = $rin, undef, undef, 0.2);

		my $got = sysread($sock, my $data, 65536);
		return 1 if !defined $got || $got == 0;
	}

	return 0;
}

my $socket_path = Class::Shared::socket_path($dir);

# The backend is up once a connection is greeted.
my ($hog, $hog_id);
for (1 .. 100) {
	($hog, $hog_id) = new_connection($socket_path, 'Shared::Counter');
	last if $hog;
	select(undef, undef, undef, 0.05);
}

ok($hog, 'a unix backend with a small reply queue came up');
BAIL_OUT('no backend to test against') unless $hog;

# A second client, which does read, connected and ready before any reply has to
# be queued: whatever the backend does with the first client's reply, this
# client's request must not have to wait for it.
my ($other, $other_id) = new_connection($socket_path, 'Shared::Counter');
BAIL_OUT('the second client could not be set up') unless $other;

# ---- 1. A reply larger than the queue may hold.

# 16 MiB back against an 8 MiB queue: twice what the client may hold unwritten,
# so the reply cannot be queued and the connection is finished.  Nothing is read
# from this socket until the drop is looked for.
BAIL_OUT('cannot send the 16 MiB request') unless send_frame($hog, {
	op     => 'call',
	id     => $hog_id,
	method => 'blob',
	args   => [16 * 1024 * 1024],
	want   => 'scalar',
});

my $started = Time::HiRes::time();
my $value = ask($other, {
	op     => 'call',
	id     => $other_id,
	method => 'value',
	args   => [],
	want   => 'scalar',
});
my $elapsed = Time::HiRes::time() - $started;

ok($value && $value->{ok}, 'a second client is served while the reply cannot be queued')
	or diag 'the second client got no answer';
is($value->{result}[0], 0, 'with an object of its own') if $value && $value->{ok};
cmp_ok($elapsed, '<', 3,
	"and served at once, not when the queue drains ($elapsed s)");

ok(read_until_closed($hog),
	'the client that will not read is dropped when its queue passes the bound');

# Counted while this client's socket is still open: a backend that had not
# destroyed its object would report two here, not one.
is(objects_held($dir), 1,
	"only the second client's object is left: the dropped client's was destroyed");

# The bound, not a write error or a client that closed politely, is why.
like(slurp($log),
	qr/a reply of \d+ bytes leaves \d+ waiting to be written, more than the \Q$limit\E a client may hold/,
	'and the log says it was the queue bound that dropped it');

close $hog;

# ---- 2. A reply the queue can hold, written a piece at a time.

# 4 MiB fits the 8 MiB bound, but no unix socket buffer takes it at once, so the
# backend writes what the socket takes, keeps the rest queued, and must go on
# serving while this client reads none of it.
my ($holder, $holder_id) = new_connection($socket_path, 'Shared::Counter');
BAIL_OUT('the client that reads late could not be set up') unless $holder;

BAIL_OUT('cannot send the 4 MiB request') unless send_frame($holder, {
	op     => 'call',
	id     => $holder_id,
	method => 'blob',
	args   => [4 * 1024 * 1024],
	want   => 'scalar',
});

$started = Time::HiRes::time();
$value = ask($other, {
	op     => 'call',
	id     => $other_id,
	method => 'value',
	args   => [],
	want   => 'scalar',
});
$elapsed = Time::HiRes::time() - $started;

ok($value && $value->{ok}, 'a reply that only partly fits does not hold the loop')
	or diag 'the second client got no answer';
cmp_ok($elapsed, '<', 3,
	"and it is still served at once ($elapsed s)");

is(objects_held($dir), 2, 'the client that reads late is kept, since its reply fits');

# Now read it: what was queued has to arrive whole, in order, after what the
# socket took at first.
my ($late) = Class::Shared::Protocol::read_frame($holder, 10);
ok($late && $late->{ok}, 'the client that read late still gets its reply');
is(length($late->{result}[0]), 4 * 1024 * 1024, 'and the whole of it')
	if $late && $late->{ok};

close $holder;
close $other;

# ---- 3. A reply the queue can hold, and nobody reads: the deadline.

my $stall_dir = File::Spec->catdir($dir, 'stall');
mkdir $stall_dir, 0700 or BAIL_OUT("cannot make $stall_dir: $!");
my $stall_log = "$stall_dir/write.log";

my $stall_pid = start_backend($stall_dir, $stall_log, write_timeout => 1);
my $stall_path = Class::Shared::socket_path($stall_dir);

my ($quiet, $quiet_id);
for (1 .. 100) {
	($quiet, $quiet_id) = new_connection($stall_path, 'Shared::Counter');
	last if $quiet;
	select(undef, undef, undef, 0.05);
}

ok($quiet, 'a backend with a one second write timeout came up');
BAIL_OUT('no backend to test the timeout against') unless $quiet;

# 1 MiB fits the bound, but the socket takes only part of it, so the rest is
# queued.  This client reads none of it, or the queue would move again.
my $stall_started = Time::HiRes::time();
BAIL_OUT('cannot send the 1 MiB request') unless send_frame($quiet, {
	op     => 'call',
	id     => $quiet_id,
	method => 'blob',
	args   => [1024 * 1024],
	want   => 'scalar',
});

# Another client is served while that reply sits there, which is what makes
# this a timeout rather than a stall of the whole backend.
my ($during, $during_id) = new_connection($stall_path, 'Shared::Counter');
my $during_value = $during
	? ask($during, {
		op     => 'call',
		id     => $during_id,
		method => 'value',
		args   => [],
		want   => 'scalar',
	})
	: undef;

ok($during_value && $during_value->{ok},
	'another client is served while the reply makes no progress');

close $during if $during;

my $stalled;
my $give_up = $stall_started + 5;
while (Time::HiRes::time() < $give_up) {
	last if ($stalled = slurp($stall_log)) =~ /made no progress/;
	select(undef, undef, undef, 0.05);
}

my $stall_elapsed = Time::HiRes::time() - $stall_started;

like($stalled,
	qr/a queued reply of \d+ bytes made no progress for 1 second/,
	'and the connection that stops reading is dropped when the deadline passes');
cmp_ok($stall_elapsed, '>=', 0.9,
	"not before its deadline ($stall_elapsed s)");

# The other client has gone, so nothing at all should be left here.
my $left = '?';
for (1 .. 50) {
	$left = objects_held($stall_dir);
	last if $left == 0;
	select(undef, undef, undef, 0.1);
}

is($left, 0, 'and the object of the client that timed out is destroyed');

close $quiet;

my ($stall_stopped, $stall_status) = run_cli($stall_dir, 'stop');
is($stall_status, 0, 'the timing out backend stops') or diag $stall_stopped;

waitpid($stall_pid, 0);
is($?, 0, 'and exits cleanly');

# ---- 4. The whole backend has a ceiling, not just each client.

my $total_dir = File::Spec->catdir($dir, 'total');
mkdir $total_dir, 0700 or BAIL_OUT("cannot make $total_dir: $!");
my $total_log = "$total_dir/total.log";

# Each client may hold 8 MiB, but all of them together only 6 MiB: one 4 MiB
# reply fits both, and a second one fits the per-client bound and not the total.
my $total_pid = start_backend(
	$total_dir,
	$total_log,
	max_queued       => 8 * 1024 * 1024,
	max_queued_total => 6 * 1024 * 1024,
);

my $total_path = Class::Shared::socket_path($total_dir);

my ($first, $first_id);
for (1 .. 100) {
	($first, $first_id) = new_connection($total_path, 'Shared::Counter');
	last if $first;
	select(undef, undef, undef, 0.05);
}

ok($first, 'a backend with a total queue ceiling came up');
BAIL_OUT('no backend to test the total ceiling against') unless $first;

# Within both bounds; left unread, so most of it stays queued.
BAIL_OUT('cannot send the first 4 MiB request') unless send_frame($first, {
	op     => 'call',
	id     => $first_id,
	method => 'blob',
	args   => [4 * 1024 * 1024],
	want   => 'scalar',
});

my ($second, $second_id) = new_connection($total_path, 'Shared::Counter');
BAIL_OUT('the client that would pass the total could not connect') unless $second;

# Another 4 MiB fits this client's own bound and would push the backend over
# its allowance, so the reply is refused rather than queued.
BAIL_OUT('cannot send the second 4 MiB request') unless send_frame($second, {
	op     => 'call',
	id     => $second_id,
	method => 'blob',
	args   => [4 * 1024 * 1024],
	want   => 'scalar',
});

ok(read_until_closed($second),
	'the client whose reply would pass the total is dropped');

like(slurp($total_log),
	qr/queued across all clients, more than the 6291456 the backend may hold/,
	'and the log says it was the total, not one client');

is(objects_held($total_dir), 1,
	'and the client that was already queued keeps its object');

close $first;
close $second;

# Closing the queued client discards what was waiting for it, so the backend's
# count of queued bytes has to come back to nothing.
my $admin = connect_unix($total_path);
my $admin_hello = $admin
	? ask($admin, { op => 'hello', proto => $Class::Shared::PROTOCOL_VERSION })
	: undef;
my $admin_ping = $admin_hello && $admin_hello->{ok}
	? ask($admin, { op => 'ping' })
	: undef;

is($admin_ping ? $admin_ping->{queued} : 'no answer', 0,
	'and the backend is holding nothing queued once they have gone');

close $admin if $admin;

my ($total_stopped, $total_status) = run_cli($total_dir, 'stop');
is($total_status, 0, 'the capped backend stops') or diag $total_stopped;

waitpid($total_pid, 0);
is($?, 0, 'and exits cleanly');

# ---- the first backend, still holding nothing.

my ($stopped, $stopped_status) = run_cli($dir, 'stop');
is($stopped_status, 0, 'the first backend stops') or diag $stopped;

waitpid($pid, 0);
is($?, 0, 'and exits cleanly');
undef $pid;

ok(!-e $socket_path, 'leaving no socket behind');

done_testing();
