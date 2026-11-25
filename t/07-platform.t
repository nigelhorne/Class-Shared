use strict;
use warnings;

use Test::More;

use Class::Shared ();
use File::Temp qw(tempdir);

# The guard asks whether this perl can make a unix domain socket, not what
# operating system it reports, so a perl without them is refused wherever it
# runs.  The answer can be given as an argument, so the refusal is exercised by
# the suite that Linux, the BSDs and macOS run, rather than being code that only
# ever runs where it cannot be seen.
eval { Class::Shared::_require_unix_sockets('a backend', 0); 1 };
like($@, qr/is not available here/, 'a perl without unix sockets is refused, with a reason');
like($@, qr/no unix domain sockets/, 'naming what is missing');
like($@, qr/Unix-only/, 'and says the distribution is Unix-only');
like($@, qr/PLATFORMS/, 'pointing at the section that explains it');

eval { Class::Shared::_require_unix_sockets('a backend', 1); 1 };
is($@, '', 'a perl that has them is not refused');

# The guard is wired into the two calls a backend makes, so what a user without
# the sockets sees is the explanation rather than "writable by group or others".
# The probe's answer is forced through its cache, so this runs the same way
# everywhere: what is tested is the wiring, not whether this machine happens to
# be the one without the sockets.
{
	local $Class::Shared::UNIX_SOCKETS = 0;

	for my $attempt (
		['ensure_dir', sub { Class::Shared::ensure_dir(tempdir(CLEANUP => 1)) }],
		['socket_path', sub { Class::Shared::socket_path(tempdir(CLEANUP => 1)) }],
	) {
		my ($name, $code) = @{$attempt};

		my $returned = eval { $code->(); 1 };

		like($@, qr/no unix domain sockets/, "$name refuses a perl without them");
		like($@, qr/PLATFORMS/, "and $name points at the section that explains it");
		ok(!$returned, "and $name does not pretend to work");
	}
}

# On a platform that really has them, and owner-only directories to put them
# in, the same calls work: the refusal is about the capability and nothing else.
# Windows has the second half of that neither, whatever its sockets do, so only
# the refusal above is checked there.
SKIP: {
	skip 'MSWin32 has no POSIX directory permissions to check', 3
		if $^O eq 'MSWin32';

	ok(Class::Shared::_has_unix_sockets(), 'this perl has unix domain sockets');

	my $dir = tempdir(CLEANUP => 1);

	my ($ok, $why) = Class::Shared::ensure_dir($dir);
	ok($ok, 'ensure_dir accepts an owner-only directory') or diag $why;
	like(Class::Shared::socket_path($dir), qr/\Qclass-shared.sock\E\z/,
		'and socket_path names the backend socket inside it');
}

done_testing();
