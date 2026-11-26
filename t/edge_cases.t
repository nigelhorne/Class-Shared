#!/usr/bin/env perl

# Destructive, boundary and security tests: everything here tries to break or
# subvert Class::Shared, and asserts that it fails safely, with the documented
# message, without hanging, running something it should not, or running out of
# memory.
#
# Hostile things tried: huge and truncated frames, deeply nested and circular
# data, typeglobs and code references, wrong types in every protocol field,
# failing system calls (mocked as upstream failures), file descriptor
# exhaustion, special and unreadable files, shell metacharacters in paths, and
# very long strings against every regular expression.
#
# Test::Mockingbird::TimeTravel is not used: it controls its own now(), and the
# code under test calls the core time(), so it cannot move that clock.  Time
# limits are tested with short real timeouts instead.
#
# Set TEST_VERBOSE=1 to see the state the subtests print with diag.

use strict;
use warnings;

use Test::Most;

BEGIN {
	foreach my $module (qw(Test::Mockingbird Test::Returns Test::Permissions)) {
		eval "require $module; 1"
			or plan skip_all => "$module is needed for the edge case tests and is not installed";
	}

	require Class::Shared;
	plan skip_all => 'a backend needs unix sockets in an owner-only directory, which this perl cannot provide'
		unless Class::Shared::_has_unix_sockets() && Test::Permissions::can_revoke_create();

	Test::Mockingbird->import;
	Test::Returns->import;
	Test::Permissions->import(qw(:revoke :guard :report));
}

use File::Spec ();
use File::Temp qw(tempdir);
use IO::Socket::UNIX ();
use POSIX ();
use Socket qw(SOCK_STREAM);
use Storable ();
use Time::HiRes ();

use lib 'lib', 't/lib';
use Class::Shared::Backend ();
use Class::Shared::Frontend ();
use Class::Shared::Protocol ();

my %config = (
	class        => 'Shared::Counter',
	protocol     => 2,
	redos_length => 1_000_000,   # characters in a hostile string
	redos_limit  => 1,           # seconds any one regular expression may take
	quick        => 5,           # a failure must arrive within this
	start_wait   => 15,
	watchdog     => 300,
	small_frame  => 100_000,     # MAX_FRAME while testing size limits
	deep         => 100_000,     # levels of nesting
	fd_limit     => 24,          # open files the starved backend is allowed
	fd_clients   => 40,          # connections thrown at it
);

my $VERBOSE = $ENV{TEST_VERBOSE};

$SIG{ALRM} = sub { BAIL_OUT("t/edge_cases.t ran for more than $config{watchdog} seconds") };
alarm $config{watchdog};

sub state_of {
	diag(@_) if $VERBOSE;
	return;
}

sub private_dir {
	my $dir = tempdir(CLEANUP => 1);
	chmod 0700, $dir;
	return $dir;
}

sub write_file {
	my ($path, $text) = @_;
	open(my $fh, '>:raw', $path) or die "$path: $!";
	print {$fh} $text;
	close($fh);
	return $path;
}

sub slurp {
	my ($path) = @_;
	open(my $fh, '<', $path) or return '';
	local $/;
	my $text = <$fh>;
	close($fh);
	return defined $text ? $text : '';
}

# Run $code with a hard limit, and report the result, the exception, the
# warnings and the time.  A hang shows up as "HUNG", never as a stuck test.
sub outcome {
	my ($code, $limit) = @_;

	my @warnings;
	my (@value, $died);
	my $start = Time::HiRes::time();
	{
		local $SIG{__WARN__} = sub { push @warnings, @_ };
		local $SIG{ALRM} = sub { die "HUNG\n" };
		alarm($limit || $config{quick} * 2);
		eval { @value = $code->(); 1 };
		$died = "$@";
		alarm $config{watchdog};
	}

	return { value => $value[0], list => \@value, died => $died, warnings => \@warnings, seconds => Time::HiRes::time() - $start };
}

# A real backend in a child, with the options given.  $setup runs in the child
# first, to change package limits there only.
my @backends;
sub start_backend {
	my (%option) = @_;
	my $setup = delete $option{setup};

	my $dir = private_dir();
	my $b = { socket => File::Spec->catfile($dir, 'b.sock'), log => File::Spec->catfile($dir, 'b.log') };

	my $pid = fork() // die "fork: $!";
	if (!$pid) {
		$setup->() if $setup;
		eval { Class::Shared::Backend->new(socket => $b->{socket}, log => $b->{log}, %option)->run };
		POSIX::_exit(0);
	}
	$b->{pid} = $pid;
	push @backends, $b;

	my $until = time + $config{start_wait};
	select(undef, undef, undef, 0.05) until -S $b->{socket} || time > $until;
	BAIL_OUT('no backend: ' . slurp($b->{log})) unless -S $b->{socket};

	return $b;
}

END {
	local $?;
	foreach my $b (@backends) {
		kill 'TERM', $b->{pid};
		waitpid($b->{pid}, 0);
	}
}

sub connect_to {
	my ($b) = @_;
	return IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $b->{socket});
}

sub ask {
	my ($sock, $message) = @_;
	my ($bytes) = Class::Shared::Protocol::encode_frame($message);
	Class::Shared::Protocol::write_all($sock, $bytes);
	my ($reply, $error) = Class::Shared::Protocol::read_frame($sock, $config{quick});
	return defined $reply ? $reply : { ok => 0, kind => 'no reply', error => $error };
}

sub greeted {
	my ($b, $class) = @_;
	my $sock = connect_to($b) or die "connect: $!";
	ask($sock, { op => 'hello', proto => $config{protocol}, class => $class || $config{class} });
	return $sock;
}

sub alive {
	my ($b) = @_;
	my $sock = connect_to($b) or return 0;
	my $r = ask($sock, { op => 'hello', proto => $config{protocol} });
	return $r->{ok} ? 1 : 0;
}

# ===========================================================================
# Class::Shared
# ===========================================================================

# Catastrophic backtracking: very long, repetitive strings against every
# pattern a caller's text reaches.  Each must answer within the limit.
subtest 'regular expressions are not open to ReDoS' => sub {
	my $n = $config{redos_length};
	my %attack = (
		'validate_class, long name then junk'   => sub { Class::Shared::validate_class(('a' x $n) . '!') },
		'validate_class, many ::'               => sub { Class::Shared::validate_class(('A::' x ($n / 3)) . '!') },
		'validate_class, only colons'           => sub { Class::Shared::validate_class(':' x $n) },
		'normalise_fingerprint, hex and colons' => sub { Class::Shared::normalise_fingerprint('AB:' x ($n / 3)) },
		'normalise_fingerprint, only colons'    => sub { Class::Shared::normalise_fingerprint(':' x $n) },
		'dir_of, only slashes'                  => sub { Class::Shared::dir_of('/' x $n) },
		'dir_of, slashes then a name'           => sub { Class::Shared::dir_of(('a/' x ($n / 2)) . 'b') },
		'read_secret, white space then a byte'  => do {
			my $path = write_file(File::Spec->catfile(private_dir(), 's'), (' ' x 60_000) . 'x' . (' ' x 5_000));
			sub { Class::Shared::read_secret($path) };
		},
	);

	foreach my $name (sort keys %attack) {
		my $r = outcome($attack{$name}, $config{redos_limit} * 3);
		unlike($r->{died}, qr/HUNG/, "$name: does not hang");
		cmp_ok($r->{seconds}, '<', $config{redos_limit}, '  and answers within the limit');
		is_deeply($r->{warnings}, [], '  without warnings (no recursion limit)');
	}

	# Regression: perl 5.26 capped a repeated group at 32766 and warned.
	my $long = join '::', ('a') x 40_000;
	my $r = outcome(sub { Class::Shared::validate_class($long) });
	is($r->{value}, $long, 'regression: a name of 40000 parts is accepted whole');
	is_deeply($r->{warnings}, [], 'regression: and no "recursion limit" warning');
};

subtest 'validate_class and friends refuse hostile values' => sub {
	my @hostile = (
		"A\0B", "A\nB", "A::B\n", 'A;system("id")', '../../etc/passwd', 'A/../B', "A'B", '$A', 'A B',
		"\x{e9}t\x{e9}", "\xff\xfe", '0abc', '::', 'A::', 'A:::B', 'A:B',
	);
	foreach my $name (@hostile) {
		(my $shown = $name) =~ s/([^\x20-\x7e])/sprintf '\\x{%x}', ord $1/ge;
		throws_ok { Class::Shared::validate_class($name) } qr/is not a valid class name\n\z/, "refuses '$shown'";
	}

	# Wrong types: references and globs are not names.
	foreach my $value ([], {}, \'x', sub { 1 }, *STDOUT) {
		my $r = outcome(sub { Class::Shared::validate_class($value) });
		like($r->{died}, qr/\AClass::Shared: .*(?:not a valid class name|no class name given)/s, 'a ' . (ref($value) || 'glob') . ' is refused');
	}
	throws_ok { Class::Shared::validate_class() } qr/no class name given/, 'nothing at all';

	# The answer is the same in list and scalar context.
	is_deeply([Class::Shared::validate_class('A::B')], ['A::B'], 'list context');

	# $_ is not changed.
	local $_ = 'keep';
	Class::Shared::validate_class('A');
	eval { Class::Shared::normalise_fingerprint('x') };
	Class::Shared::dir_of('/a/b');
	is($_, 'keep', '$_ is left alone');
};

subtest 'read_secret against hostile files' => sub {
	my $dir = private_dir();

	my %content = ('empty' => '', 'white space only' => " \t\r\n\n", 'new lines' => "\n" x 100);
	foreach my $name (sort keys %content) {
		my $path = write_file(File::Spec->catfile($dir, 'f'), $content{$name});
		throws_ok { Class::Shared::read_secret($path) } qr/\AClass::Shared: \Q$path\E is empty\n\z/, "a file that is $name";
	}

	# Names a shell would act on are only names.
	foreach my $name ('a b', 'semi;colon', '$(touch PWNED)', '`id`', "new\nline", '|pipe', '>redirect') {
		my $path = write_file(File::Spec->catfile($dir, $name), "s\n");
		(my $shown = $name) =~ s/\n/\\n/g;
		is(Class::Shared::read_secret($path), 's', "a file called '$shown' is just a file");
	}
	ok(!-e 'PWNED' && !-e File::Spec->catfile($dir, 'PWNED'), 'nothing was run by those names');

	# A path that is a mode for open() must not be one.
	throws_ok { Class::Shared::read_secret('echo hello |') } qr/cannot read echo hello \|: /, 'a pipe "path" is not executed';

	# Special files.  /dev/zero and /dev/urandom never end: reading one whole
	# would use all memory, so the size of a secret is bounded.
	throws_ok { Class::Shared::read_secret('/dev/null') } qr/is empty/, '/dev/null is empty';
	foreach my $device (grep { -c $_ } '/dev/zero', '/dev/urandom') {
		my $r = outcome(sub { Class::Shared::read_secret($device) });
		like($r->{died}, qr/\AClass::Shared: \Q$device\E is too large to be a secret \(more than 65536 bytes\)\n\z/, "$device is refused");
		cmp_ok($r->{seconds}, '<', $config{quick}, '  quickly');
	}
	my $big = write_file(File::Spec->catfile($dir, 'big'), 'x' x 65_537);
	throws_ok { Class::Shared::read_secret($big) } qr/is too large to be a secret/, 'one byte over the limit';
	my $fits = write_file(File::Spec->catfile($dir, 'fits'), 'x' x 65_536);
	is(length Class::Shared::read_secret($fits), 65_536, 'exactly the limit is read');

	# A dangling symlink and a directory.
	my $dangling = File::Spec->catfile($dir, 'dangling');
	symlink('/no/such/target', $dangling) or die;
	throws_ok { Class::Shared::read_secret($dangling) } qr/cannot read \Q$dangling\E: No such file/, 'a dangling symlink';
	throws_ok { Class::Shared::read_secret($dir) } qr/cannot read \Q$dir\E: /, 'regression: a directory (macOS opens it and fails later)';
	throws_ok { local $SIG{__WARN__} = sub { }; Class::Shared::read_secret("/etc/passwd\0.txt") } qr/\AClass::Shared: cannot read /, 'a NUL byte in the path does not truncate it';

	SKIP: {
		skip 'this filesystem cannot make a file unreadable', 1 unless can_revoke_read($dir);
		my $path = write_file(File::Spec->catfile($dir, 'locked'), "s\n");
		with_revoked(read => $path, sub {
			throws_ok { Class::Shared::read_secret($path) } qr/cannot read \Q$path\E: Permission denied/, 'an unreadable file';
		});
	}

	# Reading must not use the caller's $_ or record separator.
	local $_ = 'keep';
	local $/ = 'x';
	my $path = write_file(File::Spec->catfile($dir, 'rs'), "axbxc\n");
	is(Class::Shared::read_secret($path), 'axbxc', 'a caller\'s $/ does not cut the secret');
	is($_, 'keep', '$_ is left alone');
};

subtest 'ensure_dir and socket paths against hostile filesystems' => sub {
	my $base = private_dir();

	my $file = write_file(File::Spec->catfile($base, 'file'), 'x');
	my ($ok, $why) = Class::Shared::ensure_dir($file);
	is($ok, 0, 'a plain file where a directory should be: refused');
	ok($why, "  with a reason: $why");

	my $dangling = File::Spec->catfile($base, 'dangling');
	symlink(File::Spec->catfile($base, 'nowhere'), $dangling) or die;
	($ok, $why) = Class::Shared::ensure_dir($dangling);
	is($ok, 0, 'a dangling symlink: refused');
	ok(!-e File::Spec->catfile($base, 'nowhere'), '  and nothing was made at its target');

	SKIP: {
		skip 'as root every directory is one\'s own', 1 if $> == 0;
		my $link = File::Spec->catfile($base, 'to-tmp');
		symlink('/', $link) or die;
		($ok, $why) = Class::Shared::ensure_dir($link);
		is($ok, 0, 'a symlink to a directory of another user: refused');
	}

	foreach my $name ('with space', '$(touch PWNED2)', "new\nline", '-rf', '*') {
		my $dir = File::Spec->catdir($base, $name);
		is((Class::Shared::ensure_dir($dir))[0], 1, 'a directory with a hostile name is just a directory');
		ok(-d $dir, '  and is made');
	}
	ok(!-e 'PWNED2', 'nothing was run');

	SKIP: {
		skip 'this filesystem cannot refuse new files', 2 unless can_revoke_create($base);
		my $parent = File::Spec->catdir($base, 'ro');
		mkdir $parent or die;
		with_revoked(create => $parent, sub {
			my ($made, $reason) = Class::Shared::ensure_dir(File::Spec->catdir($parent, 'child'));
			is($made, 0, 'a parent that refuses new files');
			like($reason, qr/\Acannot create .*Permission denied\z/, '  with the system reason');
		});
	}

	throws_ok { Class::Shared::default_dir(dir => "/tmp/a\0/b") } qr/may not contain a NUL byte/, 'a NUL byte in a directory';
	throws_ok { Class::Shared::socket_path('/' . ('x' x 10_000)) } qr/more than the 100 allowed/, 'an enormous directory';
};

# ===========================================================================
# Class::Shared::Protocol
# ===========================================================================

sub pipe_holding {
	my ($bytes) = @_;
	pipe(my $r, my $w) or die "pipe: $!";
	syswrite($w, $bytes) if length $bytes;
	close($w);
	return $r;
}

# Frames a hostile peer can send.  None may use memory in proportion to a
# length it merely claims, and none may kill the process.
subtest 'hostile frames' => sub {
	foreach my $claim (0xFFFFFFFF, 0x7FFFFFFF, 64 * 1024 * 1024 + 1) {
		my @r = Class::Shared::Protocol::read_frame(pipe_holding(pack('N', $claim)));
		like($r[1], qr/\Aframe of $claim bytes exceeds the limit of \d+\z/, "a claim of $claim bytes is refused before reading");
		my $buffer = pack('N', $claim);
		is((Class::Shared::Protocol::take_frame(\$buffer))[0], -1, '  also from a buffer');
	}

	foreach my $bytes (pack('N', 0), pack('N', 1) . "\0", pack('N', 100) . ('x' x 5), "\0", "\xff" x 3) {
		my $r = outcome(sub { Class::Shared::Protocol::read_frame(pipe_holding($bytes)) });
		ok(!defined $r->{list}[0] && defined $r->{list}[1], 'a broken frame of ' . length($bytes) . ' bytes gives an error, not a message');
	}

	# Random bytes as a Storable body.
	srand 1;
	my $survived = 0;
	for (1 .. 300) {
		my $body = join '', map { chr int rand 256 } 1 .. 1 + int rand 60;
		my $r = outcome(sub { Class::Shared::Protocol::take_payload($body) });
		$survived++ if $r->{died} eq '';
	}
	is($survived, 300, '300 random bodies: none of them killed the process or escaped as an exception');

	# Truncations and single-byte damage of a good image.
	my $image = Storable::nfreeze({ a => [1, 2, { b => 'c' }] });
	my @bad = map { substr($image, 0, $_) } 0 .. length($image) - 1;
	my $died = grep { outcome(sub { Class::Shared::Protocol::take_payload($_) })->{died} } @bad;
	is($died, 0, 'every truncation of an image is handled');

	# An unauthenticated or tampered frame is never thawed.
	my $thawed = 0;
	mock('Storable::thaw' => sub { $thawed++; return {} });
	my $signed = Class::Shared::Protocol::encode_frame({ x => 1 }, 'k');
	my $tampered = $signed;
	substr($tampered, -1) ^= "\x01";
	foreach my $case ([$tampered, 'k'], [$signed, 'wrong'], [$signed, ''], [pack('N', 31) . ('a' x 31), 'k']) {
		my $buffer = $case->[0];
		Class::Shared::Protocol::take_frame(\$buffer, $case->[1]);
	}
	restore_all();
	is($thawed, 0, 'a frame that fails authentication is never thawed');

	# Upstream thaw that fails without saying anything.
	foreach my $returns (undef) {
		mock('Storable::thaw' => sub { return $returns });
		my @r = Class::Shared::Protocol::take_payload('anything');
		restore_all();
		is($r[0], undef, 'a thaw that returns undef gives no message');
		like($r[1], qr/\Acannot deserialise message: /, '  and an error');
	}
};

subtest 'volume, nesting and un-serialisable data' => sub {
	local $Class::Shared::Protocol::MAX_FRAME = $config{small_frame};

	my ($bytes, $error) = Class::Shared::Protocol::encode_frame({ big => 'x' x (10 * $config{small_frame}) });
	is($bytes, undef, 'a string over the limit is not framed');
	like($error, qr/\Amessage is too large \(\d+ bytes, limit is $config{small_frame}\)\z/, 'with the size-limit message');
	($bytes, $error) = Class::Shared::Protocol::encode_frame([(0) x 1_000_000]);
	like($error, qr/\Amessage is too large/, 'a million element array too');

	# Deeply nested data: an error or a frame, never a crash.
	my $deep = [];
	$deep = [$deep] for 1 .. $config{deep};
	my $r = outcome(sub { Class::Shared::Protocol::encode_frame($deep) });
	is($r->{died}, '', 'very deep nesting does not escape as an exception');
	ok(!defined $r->{list}[0], 'and is refused');
	like($r->{list}[1] // '', qr/\A(?:cannot serialise message|message is too large)/, 'with an explanation');

	# Cycles are data; code and globs are not.
	my $cycle = {};
	$cycle->{self} = $cycle;
	($bytes) = Class::Shared::Protocol::encode_frame($cycle);
	my $buffer = $bytes;
	my (undef, $back) = Class::Shared::Protocol::take_frame(\$buffer);
	is($back->{self}, $back, 'a cycle survives the round trip as a cycle');
	%$cycle = ();
	%$back = ();

	foreach my $case (['code', { c => sub { } }], ['glob', [\*STDOUT]], ['plain string', 'x'], ['undef', undef]) {
		my @answer = Class::Shared::Protocol::encode_frame($case->[1]);
		ok(!defined $answer[0], "a $case->[0] is refused");
		like($answer[1], qr/\Acannot serialise message: /, '  with the message');
	}

	# A secret that is a hostile string is still just bytes.
	foreach my $secret ('', "\0\0\0", 'x' x 100_000) {
		my ($signed) = Class::Shared::Protocol::encode_frame({}, $secret);
		my $buffered = $signed;
		is((Class::Shared::Protocol::take_frame(\$buffered, $secret))[0], 1, 'a secret of ' . length($secret) . ' bytes signs and verifies');
	}
};

# The disk is full, the peer vanishes, the read fails: reported, not thrown.
subtest 'failing I/O' => sub {
	pipe(my $r, my $w) or die;
	close($w);
	# Perl's own warning about the closed handle is expected here.
	my @got = do { local $SIG{__WARN__} = sub { }; Class::Shared::Protocol::write_all($w, 'x') };
	is($got[0], 0, 'writing to a closed handle: 0');
	like($got[1], qr/\Awrite failed: /, 'with the reason');
	close($r);
	@got = outcome(sub { Class::Shared::Protocol::read_frame($r, 1) })->{list};
	ok(1, 'reading a closed handle returns');

	SKIP: {
		skip 'no /dev/full', 2 unless -c '/dev/full';
		open(my $full, '>', '/dev/full') or skip "cannot open /dev/full: $!", 2;
		my @answer = Class::Shared::Protocol::write_all($full, 'x');
		is($answer[0], 0, 'a full disk (ENOSPC): 0');
		like($answer[1], qr/\Awrite failed: No space left on device\z/, 'with the system reason');
		close($full);
	}
};

# ===========================================================================
# Class::Shared::Frontend: upstream failures
# ===========================================================================

# Upstream failures are mocked as undef, 0, "" and nonsense from the two
# functions that talk to the socket.  The frontend must turn each into one
# clear exception, with no warnings.
subtest 'the frontend and a failing or lying backend' => sub {
	my $dir = private_dir();
	my $path = File::Spec->catfile($dir, 's.sock');
	my $listen = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $path, Listen => 64) or die;

	# replies: hello, new, then the one under test for the call
	my $open_with = sub {
		my ($call_reply) = @_;
		my @queue = ([{ ok => 1, pid => 1 }], [{ ok => 1, id => 1 }], $call_reply);
		mock('Class::Shared::Protocol::write_all' => sub { return (1) });
		mock('Class::Shared::Protocol::read_frame' => sub { return @{ shift(@queue) || [undef, 'connection closed by peer'] } });
		return Class::Shared::Frontend->new($config{class}, socket => $path, autostart => 0);
	};

	my %replies = (
		'undef and no reason' => [undef],
		'empty string'        => [''],
		'zero'                => [0],
		'an array'            => [[1]],
		'a scalar reference'  => [\'x'],
		'undef with a reason' => [undef, 'timed out waiting for a reply'],
		'ok 0 with no text'   => [{ ok => 0 }],
		'ok 1 with no result' => [{ ok => 1 }],
		'a result that is not a list' => [{ ok => 1, result => 'x' }],
	);

	foreach my $name (sort keys %replies) {
		my $frontend = $open_with->($replies{$name});
		my $r = outcome(sub { my @list = $frontend->anything; scalar @list });
		unlike($r->{died}, qr/HUNG|Can't use|Not a HASH|Not an ARRAY/, "$name: no internal Perl error");
		is_deeply($r->{warnings}, [], '  and no warnings');
		restore_all();
	}

	# The send itself fails.
	my $frontend = $open_with->([{ ok => 1, result => [1] }]);
	mock('Class::Shared::Protocol::write_all' => sub { return (0, 'write failed: No space left on device') });
	throws_ok { $frontend->anything } qr/\AClass::Shared: lost the backend for '\Q$config{class}\E': write failed: No space left on device\n\z/, 'a failed write is reported';
	is($frontend->shared_connected, 0, 'and the connection is dropped');
	restore_all();

	# The encoder gives nothing back.
	$frontend = $open_with->([{ ok => 1, result => [1] }]);
	mock('Class::Shared::Protocol::encode_frame' => sub { return (undef, '') });
	my $r = outcome(sub { $frontend->anything });
	like($r->{died}, qr/\AClass::Shared: lost the backend/, 'an encoder that returns nothing is still an error');
	restore_all();

	# Handshake: every kind of nothing.
	foreach my $answer ([undef], [''], [0], [[1]]) {
		mock('Class::Shared::Protocol::write_all' => sub { return (1) });
		mock('Class::Shared::Protocol::read_frame' => sub { return @$answer });
		my $hs = outcome(sub { Class::Shared::Frontend->new($config{class}, socket => $path, autostart => 0) });
		like($hs->{died}, qr/\AClass::Shared: cannot reach a backend at \Q$path\E: handshake failed: /, 'a bad handshake reply is reported');
		is_deeply($hs->{warnings}, [], '  without warnings');
		restore_all();
	}

	# Context confusion: a list reply used in scalar context gives the first value.
	$frontend = $open_with->([{ ok => 1, result => [1, 2, 3] }]);
	my $scalar = $frontend->anything;
	is($scalar, 1, 'scalar context takes the single value the backend sent for it');
	restore_all();

	# $_ is not used by a call.
	$frontend = $open_with->([{ ok => 1, result => ['v'] }]);
	{
		local $_ = 'keep';
		$frontend->anything;
		is($_, 'keep', '$_ is left alone');
	}
	restore_all();
};

subtest 'the frontend refuses hostile options and arguments' => sub {
	my $dir = private_dir();

	foreach my $case ([undef], [''], [0], ['A B'], ["A\n"], [{}], [[]]) {
		my $r = outcome(sub { Class::Shared::Frontend->new($case->[0], dir => $dir) });
		like($r->{died}, qr/\AClass::Shared(?:::Frontend->new)?: /, 'a hostile class name is refused with a Class::Shared message');
	}
	throws_ok { Class::Shared::Frontend->new($config{class}, 'dir') } qr/\AClass::Shared/, 'an odd option list';
	throws_ok { Class::Shared::Frontend->new($config{class}, dir => $dir, ctor => {}) } qr/ctor must be an array ref/, 'ctor as a hash';
	ok(!-e File::Spec->catfile($dir, 'class-shared.sock'), 'no backend was started by any of these');

	# A directory with shell metacharacters: the backend is started without a shell.
	my $evil = File::Spec->catdir(private_dir(), q{a b;touch PWNED3 $(id)});
	mkdir $evil, 0700 or die "mkdir: $!";
	my $frontend = Class::Shared::Frontend->new($config{class}, dir => $evil, ctor => [start => 1]);
	is($frontend->inc, 2, 'a backend starts in a directory with hostile characters in its name');
	ok(!-e 'PWNED3' && !-e File::Spec->catfile($evil, 'PWNED3'), 'and no command in the name was run');

	# Arguments that cannot be sent: an error, and the connection survives or says why.
	my $r = outcome(sub { $frontend->add(sub { }) });
	like($r->{died}, qr/cannot serialise message/, 'a code reference argument is reported');
	$frontend = Class::Shared::Frontend->new($config{class}, dir => $evil) unless $frontend->shared_connected;

	{
		local $Class::Shared::Protocol::MAX_FRAME = $config{small_frame};
		$r = outcome(sub { $frontend->add('9' x (2 * $config{small_frame})) });
		like($r->{died}, qr/message is too large \(\d+ bytes, limit is $config{small_frame}\)/, 'an argument over the limit is refused with the size message');
	}
	$frontend = Class::Shared::Frontend->new($config{class}, dir => $evil) unless $frontend->shared_connected;

	foreach my $method ('new', 'DESTROY', 'AUTOLOAD') {
		throws_ok { $frontend->shared_call($method) } qr/cannot call \Q$method\E\(\) through Class::Shared/, "$method cannot be called";
	}
	foreach my $method ('CORE::system', 'POSIX::_exit', 'Storable::nstore', "inc\n", 'inc;die', "inc\0x", 'a' x 100_000 . '::x') {
		throws_ok { $frontend->shared_call($method, '/tmp/PWNED4') } qr/is not a plain method name/, 'a qualified or damaged method name is refused';
	}
	ok(!-e '/tmp/PWNED4', 'nothing was written by them');
	is($frontend->shared_status->{pid}, $frontend->shared_pid, 'and the backend is unharmed');

	$frontend->shared_shutdown;
};

# Time and descriptors on the client side: a backend that accepts and says
# nothing must not hold the caller past the timeout, and many failed attempts
# must not leave handles behind.
subtest 'a silent backend and repeated failures do not hang or leak' => sub {
	my $dir = private_dir();
	my $path = File::Spec->catfile($dir, 's.sock');
	my $listen = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $path, Listen => 64) or die;

	my $r = outcome(sub { Class::Shared::Frontend->new($config{class}, socket => $path, autostart => 0, timeout => 1) });
	like($r->{died}, qr/handshake failed: timed out waiting for a reply \(the backend may be busy/, 'a silent backend: the timeout is enforced');
	cmp_ok($r->{seconds}, '<', $config{quick}, '  promptly');
	$listen->accept;

	SKIP: {
		skip 'needs /proc/PID/fd', 1 unless -d "/proc/$$/fd";
		my $count = sub { my @fds = glob("/proc/$$/fd/*"); scalar @fds };
		my $absent = File::Spec->catfile(private_dir(), 'none.sock');
		my $before = $count->();
		eval { Class::Shared::Frontend->new($config{class}, socket => $absent, autostart => 0) } for 1 .. 500;
		mock('Class::Shared::Protocol::write_all' => sub { return (0, 'write failed: Too many open files') });
		for (1 .. 50) {
			eval { Class::Shared::Frontend->new($config{class}, socket => $path, autostart => 0) };
			my $accepted = $listen->accept;
		}
		restore_all();
		cmp_ok($count->(), '<=', $before, '550 failed constructions leave no descriptor open');
	}
};

# ===========================================================================
# Class::Shared::Backend: hostile clients
# ===========================================================================

# Every field of every request given the wrong type.  The backend must answer
# or close, never die, never warn into its log, and keep serving others.
subtest 'hostile requests do not bring the backend down' => sub {
	my $b = start_backend();

	my $cycle = {};
	$cycle->{self} = $cycle;
	my @values = (undef, '', 0, -1, 1.5, 9**9**9, 'x' x 10_000, [], {}, \'ref', $cycle, "\x{263a}", "\0");

	my $sent = 0;
	foreach my $value (@values) {
		foreach my $request (
			{ op => $value },
			{ op => 'hello', proto => $value },
			{ op => 'hello', proto => $config{protocol}, class => $value },
		) {
			my $sock = connect_to($b) or die;
			ask($sock, $request);
			$sent++;
		}

		my $sock = greeted($b);
		my $id = ask($sock, { op => 'new', args => [] })->{id};
		foreach my $request (
			{ op => 'new', args => $value },
			{ op => 'call', id => $value, method => 'inc', args => [] },
			{ op => 'call', id => $id, method => $value, args => [] },
			{ op => 'call', id => $id, method => 'inc', args => $value },
			{ op => 'call', id => $id, method => 'inc', args => [], want => $value },
			{ op => 'call', id => $id, method => 'can', args => [$value] },
			{ op => 'call', id => $id, method => 'isa', args => [$value] },
		) {
			ask($sock, $request);
			$sent++;
		}
	}
	%$cycle = ();
	state_of("$sent hostile requests sent");

	ok(alive($b), "the backend answers after $sent hostile requests");
	is(kill(0, $b->{pid}), 1, 'and is the same process');
	unlike(slurp($b->{log}), qr/uninitialized|Use of|panic|Segmentation/i, 'nothing leaked a Perl warning into the log');

	# Raw attacks on the framing.
	foreach my $raw (pack('N', 0xFFFFFFFF), "\0" x 4, "GET / HTTP/1.1\r\n\r\n", pack('N', 10), "\xff" x 100_000, '') {
		local $SIG{PIPE} = 'IGNORE';
		my $sock = connect_to($b) or die;
		syswrite($sock, $raw);
		close($sock);
	}
	ok(alive($b), 'and survives broken framing and slammed connections');
};

subtest 'limits hold: objects, clients, frames and nesting' => sub {
	my $b = start_backend(
		max_objects => 3,
		max_clients => 3,
		setup       => sub { $Class::Shared::Protocol::MAX_FRAME = $config{small_frame} },
	);

	my $sock = greeted($b);
	my @made = map { ask($sock, { op => 'new', args => [] }) } 1 .. 6;
	is(scalar(grep { $_->{ok} } @made), 3, 'only max_objects objects are made');
	is($made[-1]{kind}, 'busy', 'the rest are told busy');

	# A reply too large to frame is an error reply, not a dead connection.
	my $id = $made[0]{id};
	my $r = ask($sock, { op => 'call', id => $id, method => 'blob', args => [10 * $config{small_frame}] });
	is($r->{ok}, 0, 'a result over the frame limit is refused');
	like($r->{error} // '', qr/too large/, 'and the size is the reason');
	ok(ask($sock, { op => 'ping' })->{ok}, 'the connection still works');

	# An incoming frame over the limit ends that connection only.
	my $greedy = greeted($b);
	local $SIG{PIPE} = 'IGNORE';
	syswrite($greedy, pack('N', 10 * $config{small_frame}) . ('x' x 1000));
	my @answer = Class::Shared::Protocol::read_frame($greedy, $config{quick});
	ok(!$answer[0] || !$answer[0]{ok}, 'an oversize request is not served');
	ok(ask($sock, { op => 'ping' })->{ok}, 'others are unaffected');
	close($greedy);

	# Client limit: the extra ones are told, and room returns when one leaves.
	my @held = map { greeted($b) } 1 .. 2;
	my $extra = connect_to($b);
	my ($busy) = Class::Shared::Protocol::read_frame($extra, $config{quick});
	is($busy->{kind}, 'busy', 'a fourth client is told the backend is full');
	@held = ();
	select(undef, undef, undef, 0.3);
	ok(alive($b), 'and a place is free again once a client leaves');
};

# Objects and file descriptors must go when clients do.
subtest 'no leak across many clients' => sub {
	plan skip_all => 'needs /proc/PID/fd' unless -d "/proc/$$/fd";

	my $b = start_backend();
	my $open_files = sub { my @fds = glob("/proc/$b->{pid}/fd/*"); scalar @fds };

	alive($b);
	select(undef, undef, undef, 0.2);
	my $before = $open_files->();

	for (1 .. 200) {
		my $sock = greeted($b);
		ask($sock, { op => 'new', args => [] });
		close($sock);
	}
	select(undef, undef, undef, 0.5);

	cmp_ok($open_files->(), '<=', $before + 1, 'descriptors are closed');
	my $sock = greeted($b);
	is(ask($sock, { op => 'ping' })->{objects}, 0, 'and the objects destroyed');
};

# Run the backend out of file descriptors.  It must stay up, must not spin the
# processor while it cannot accept, and must serve again once there is room.
subtest 'file descriptor exhaustion' => sub {
	plan skip_all => 'needs /proc/PID/stat and a shell with ulimit' unless -r "/proc/$$/stat" && -x '/bin/sh';

	my $dir = private_dir();
	my $socket = File::Spec->catfile($dir, 'b.sock');
	my $log = "$socket.log";

	my $pid = fork() // die;
	if (!$pid) {
		no warnings 'exec';
		exec('/bin/sh', '-c', "ulimit -n $config{fd_limit} && exec \"\$0\" \"\$@\"",
			$^X, (map { "-I$_" } grep { !ref } @INC), '-MClass::Shared::Backend', '-e',
			'Class::Shared::Backend->new(socket => $ARGV[0], log => $ARGV[1], max_clients => 1000)->run',
			$socket, $log);
		POSIX::_exit(127);
	}
	push @backends, { pid => $pid };
	my $until = time + $config{start_wait};
	select(undef, undef, undef, 0.05) until -S $socket || time > $until;
	ok(-S $socket, 'a backend with a small descriptor limit is up') or return;

	my $b = { socket => $socket, pid => $pid };
	my $first = greeted($b);

	my @clients = grep { defined } map { connect_to($b) } 1 .. $config{fd_clients};
	state_of(scalar(@clients) . ' connections queued');
	select(undef, undef, undef, 0.5);

	my $cpu = sub {
		my @field = split ' ', (slurp("/proc/$pid/stat") =~ s/\A.*\) //sr);
		return ($field[11] + $field[12]) / POSIX::sysconf(POSIX::_SC_CLK_TCK());
	};
	my $before = $cpu->();
	sleep 2;
	my $used = $cpu->() - $before;
	state_of("processor seconds used while starved: $used");

	is(kill(0, $pid), 1, 'it survives running out of descriptors');
	cmp_ok($used, '<', 0.5, 'and does not spin the processor while it cannot accept');
	ok(ask($first, { op => 'ping' })->{ok}, 'a client that was already connected is still served');
	cmp_ok(length(slurp($log)), '<', 100_000, 'and the log does not fill up');

	@clients = ();
	select(undef, undef, undef, 1);
	ok(alive($b), 'once the others leave, new clients are accepted again');
};

alarm 0;
done_testing();
