use strict;
use warnings;

use Test::More;

use Class::Shared ();
use File::Temp qw(tempdir);

# The guard takes the platform as an argument, so the refusal Windows gets is
# exercised by the suite that Linux, the BSDs and macOS run too, rather than
# being code that only ever runs where it cannot be seen.
eval { Class::Shared::_posix_only('a backend', 'MSWin32'); 1 };
like($@, qr/is not available on MSWin32/, 'MSWin32 is refused, with a reason');
like($@, qr/Unix-only/, 'and says the distribution is Unix-only');
like($@, qr/PLATFORMS/, 'pointing at the section that explains it');

eval { Class::Shared::_posix_only('a backend', 'linux'); 1 };
is($@, '', 'a POSIX system is not refused');

if ($^O eq 'MSWin32') {
	# The guard is wired into the calls a backend makes, so what a Windows user
	# sees is the explanation, not "writable by group or others".
	for my $attempt (
		['ensure_dir', sub { Class::Shared::ensure_dir(tempdir(CLEANUP => 1)) }],
		['socket_path', sub { Class::Shared::socket_path(tempdir(CLEANUP => 1)) }],
	) {
		my ($name, $code) = @{$attempt};

		my $returned = eval { $code->(); 1 };

		like($@, qr/is not available on MSWin32/, "$name refuses MSWin32");
		ok(!$returned, "and $name does not pretend to work");
	}

	done_testing();
	exit 0;
}

# On a POSIX system the same calls work, so the refusal is about the platform
# and not about the directory it was given.
my $dir = tempdir(CLEANUP => 1);

my ($ok, $why) = Class::Shared::ensure_dir($dir);
ok($ok, 'ensure_dir accepts an owner-only directory') or diag $why;
like(Class::Shared::socket_path($dir), qr/\Qclass-shared.sock\E\z/,
	'and socket_path names the backend socket inside it');

done_testing();
