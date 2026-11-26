use strict;
use warnings;

use Test::More;
use Test::Needs;
use Class::Shared ();

# Regressions found by code review.  Like the rest of the suite these need a
# unix socket in a directory only its owner can write to.
BEGIN {
	test_needs 'Test::Permissions';

	plan skip_all => 'a backend needs unix sockets in an owner-only directory, '
		. 'which this perl cannot provide (Class::Shared is Unix-only)'
		unless Class::Shared::_has_unix_sockets()
			&& Test::Permissions::can_revoke_create();
}

use File::Temp qw(tempdir);
use POSIX ();
use lib 't/lib';

use Class::Shared::Frontend;
use Class::Shared::Backend ();

my $dir = tempdir(CLEANUP => 1);

# ensure_dir is documented to return (1, undef) on success, so a caller
# that counts the list sees two elements, not one.
{
	my @result = Class::Shared::ensure_dir($dir);

	is(scalar @result, 2, 'ensure_dir returns a two element list on success');
	is($result[0], 1, 'the first element is true');
	is($result[1], undef, 'the second is undef, as documented');

	my @refused = Class::Shared::ensure_dir('/');
	is(scalar @refused, 2, 'and a two element list when it refuses');
	is($refused[0], 0, 'with a false first element');
	like($refused[1], qr/\S/, 'and a reason');
}

# A frontend must see the caller's context, however it was called: shared_call,
# AUTOLOAD and the code reference from can() all share one implementation.
my $counter = Class::Shared::Frontend->new('Shared::Counter', dir => $dir);

{
	my @list = $counter->triple;
	is_deeply(\@list, [1, 2, 3], 'AUTOLOAD: list context returns the list');

	my $scalar = $counter->one;
	is($scalar, 'one', 'AUTOLOAD: scalar context returns one value');

	my @empty = $counter->empty_list;
	is(scalar @empty, 0, 'AUTOLOAD: an empty list is empty, not (undef)');

	my @via_call = $counter->shared_call('triple');
	is_deeply(\@via_call, [1, 2, 3], 'shared_call: list context');

	is(scalar $counter->shared_call('one'), 'one', 'shared_call: scalar context');

	my $code = $counter->can('triple');
	is(ref $code, 'CODE', 'can() returns something callable');

	my @via_can = $code->($counter);
	is_deeply(\@via_can, [1, 2, 3], 'can(): the code reference keeps list context');

	# A list returned in scalar context yields its last element.
	is(scalar $code->($counter), 3, 'can(): and scalar context');

	my $before = $counter->value;
	$counter->inc(5);
	is($counter->value, $before + 5, 'void context still runs the call');
}

# Starting a second backend on a socket that is already served must fail and
# must leave the first one alone.  It used to unlink the live backend's socket
# when the failed object was destroyed, so the first backend carried on
# running but nobody could reach it again.
{
	my $socket = $counter->shared_socket_path;

	ok(-S $socket, 'the first backend is listening');

	{
		my $second = Class::Shared::Backend->new(socket => $socket, start_timeout => 0);

		eval { $second->run; 1 };

		like($@, qr/already serving|already listening/, 'the second backend refuses to start');
	}

	ok(-S $socket, 'the failed second backend did not remove the live socket');
	is($counter->shared_status->{ok}, 1, 'and the first backend still answers');

	# Merely building and discarding a Backend must not touch the path either.
	{
		my $unused = Class::Shared::Backend->new(socket => $socket);
	}

	ok(-S $socket, 'an unused Backend object does not remove the socket');

	my $fresh = Class::Shared::Frontend->new('Shared::Counter', dir => $dir, autostart => 0);
	is($fresh->shared_pid, $counter->shared_pid, 'a new frontend reaches the same backend');
}

# ------------------------------------------------------------------ messages

# Every refusal from the helpers ends in a newline, so none of them appends
# " at FILE line N" to a message meant for a person.
for my $case (
	['validate_class (none)',    sub { Class::Shared::validate_class(undef) }],
	['validate_class (bad)',     sub { Class::Shared::validate_class('not a class') }],
	['read_secret (none)',       sub { Class::Shared::read_secret(undef) }],
	['read_secret (missing)',    sub { Class::Shared::read_secret("$dir/nope") }],
	['normalise_fingerprint (none)', sub { Class::Shared::normalise_fingerprint(undef) }],
) {
	my ($name, $code) = @{$case};

	eval { $code->(); 1 };

	like($@, qr/\AClass::Shared: .*\n\z/s, "$name: one line, prefixed, newline terminated");
	unlike($@, qr/ at \S+ line \d+/, "$name: carries no source location");
}

# --------------------------------------------------------------- socket length

my $too_long = $dir . '/' . ('x' x 120) . '.sock';

eval { Class::Shared::check_socket_path($too_long) };
like($@, qr/more than the \d+ allowed/, 'check_socket_path refuses an over-long path');
is(Class::Shared::check_socket_path("$dir/ok.sock"), "$dir/ok.sock", 'and returns a short one unchanged');

eval { Class::Shared::Backend->new(socket => $too_long) };
like($@, qr/more than the \d+ allowed/, 'Backend->new refuses an over-long explicit socket');

eval { Class::Shared::Frontend->new('Shared::Counter', socket => $too_long, autostart => 0) };
like($@, qr/more than the \d+ allowed/, 'Frontend->new refuses an over-long explicit socket');

# The refusal names the socket, instead of the OS truncating it silently.
{
	my $out = qx{$^X -Ilib bin/class-shared path --socket $too_long 2>&1};
	my $status = $? >> 8;

	is($status, 1, 'class-shared path: exits 1 for an over-long --socket');
	like($out, qr/\Aclass-shared: Class::Shared: socket path/, 'and reports it like every other CLI error');
}

# ------------------------------------------------------- the failure response

is_deeply(
	Class::Shared::Backend::_failure('busy', 'full'),
	{ ok => 0, kind => 'busy', error => 'full' },
	'_failure builds the documented refusal',
);

# ---------------------------------------------------------- checked I/O helpers

{
	my $log = "$dir/helpers.log";
	my $backend = Class::Shared::Backend->new(socket => "$dir/helpers.sock", log => $log);

	open(my $fh, '<', $0) or die "cannot open $0: $!";
	close($fh);

	# Closing a handle that is already closed fails; that must be logged, not lost.
	is($backend->_close($fh, 'a test handle'), 0, 'Backend::_close reports a failed close');

	open(my $good, '<', $0) or die "cannot open $0: $!";
	is($backend->_close($good, 'a test handle'), 1, 'and a successful one');

	is($backend->_unlink("$dir/not-there"), 1, '_unlink: a file that is already gone is not a failure');

	# unlink refuses a directory, which is a real failure.
	mkdir("$dir/sub") or die "cannot mkdir: $!";
	is($backend->_unlink("$dir/sub"), 0, '_unlink: a real failure is reported');

	open(my $log_fh, '<', $log) or die "cannot read $log: $!";
	my $logged = do { local $/; <$log_fh> };
	close($log_fh) or die "cannot close $log: $!";

	like($logged, qr/cannot close a test handle/, 'the failed close reached the log');
	like($logged, qr/cannot remove \Q$dir\E\/sub/, 'the failed unlink reached the log');
	unlike($logged, qr/not-there/, 'a missing file was not logged');
}

{
	my @warnings;
	local $SIG{__WARN__} = sub { push @warnings, @_ };

	open(my $fh, '<', $0) or die "cannot open $0: $!";
	close($fh);

	is($counter->_close($fh, 'a test handle'), 0, 'Frontend::_close reports a failed close');
	like($warnings[0], qr/cannot close a test handle/, 'and carps about it');
}

# A destructor must leave the caller's $@ and $! alone.
{
	my $backend = Class::Shared::Backend->new(socket => "$dir/destroy.sock");

	local $@ = 'keep me';
	local $! = POSIX::ENOENT();

	undef $backend;

	is($@, 'keep me', 'Backend::DESTROY preserves $@');
	is($! + 0, POSIX::ENOENT(), 'and $!');
}

# ------------------------------------------------- detaching standard streams

# Done in a child process, because it replaces STDIN, STDOUT and STDERR.
{
	my $log = "$dir/detach.log";

	my $pid = fork;
	die "cannot fork: $!" unless defined $pid;

	if (!$pid) {
		my ($ok) = Class::Shared::detach_standard_streams($log);
		POSIX::_exit(2) unless $ok;
		print STDOUT "to stdout\n";
		print STDERR "to stderr\n";
		close(STDOUT);
		close(STDERR);
		POSIX::_exit(0);
	}

	waitpid($pid, 0);
	is($? >> 8, 0, 'detach_standard_streams succeeds in a child');

	open(my $log_fh, '<', $log) or die "cannot read $log: $!";
	my $text = do { local $/; <$log_fh> };
	close($log_fh) or die "cannot close $log: $!";

	like($text, qr/to stdout/, 'STDOUT went to the log');
	like($text, qr/to stderr/, 'STDERR went to the log');
}

{
	# An unwritable log is not fatal: the streams go to the null device.
	my $pid = fork;
	die "cannot fork: $!" unless defined $pid;

	if (!$pid) {
		my ($ok) = Class::Shared::detach_standard_streams("$dir/no-such-dir/x.log");
		POSIX::_exit($ok ? 0 : 2);
	}

	waitpid($pid, 0);
	is($? >> 8, 0, 'an unwritable log falls back to the null device');
}

# --------------------------------------------------------- command-line output

SKIP: {
	skip '/dev/full is not available here', 2 unless -w '/dev/full';

	my $out = qx{$^X -Ilib bin/class-shared path --dir $dir 2>&1 >/dev/full};

	is($? >> 8, 1, 'class-shared exits 1 when standard output cannot be written');
	like($out, qr/cannot write to standard output/, 'and says why');
}

# The poll interval is one number, shared.
is($Class::Shared::POLL_INTERVAL, 0.02, 'the polling interval is the documented 0.02 seconds');
is(Class::Shared::poll_pause(), undef, 'poll_pause returns nothing');

$counter->shared_shutdown;

ok(!-e $counter->shared_socket_path || !-S $counter->shared_socket_path,
	'the backend that did own the socket still removes it when it stops');

done_testing();
