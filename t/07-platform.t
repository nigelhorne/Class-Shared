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

if ($^O eq 'MSWin32') {
	ok(!Class::Shared::_has_unix_sockets(), 'this perl really has no unix domain sockets');

	# The guard is wired into the calls a backend makes, so what a Windows user
	# sees is the explanation, not "writable by group or others".
	for my $attempt (
		['ensure_dir', sub { Class::Shared::ensure_dir(tempdir(CLEANUP => 1)) }],
		['socket_path', sub { Class::Shared::socket_path(tempdir(CLEANUP => 1)) }],
	) {
		my ($name, $code) = @{$attempt};

		my $returned = eval { $code->(); 1 };

		like($@, qr/no unix domain sockets/, "$name refuses a perl without them");
		ok(!$returned, "and $name does not pretend to work");
	}

	done_testing();
	exit 0;
}

# On a platform that has them, the same calls work, so the refusal is about the
# capability and nothing else.
ok(Class::Shared::_has_unix_sockets(), 'this perl has unix domain sockets');

my $dir = tempdir(CLEANUP => 1);

my ($ok, $why) = Class::Shared::ensure_dir($dir);
ok($ok, 'ensure_dir accepts an owner-only directory') or diag $why;
like(Class::Shared::socket_path($dir), qr/\Qclass-shared.sock\E\z/,
	'and socket_path names the backend socket inside it');

done_testing();
