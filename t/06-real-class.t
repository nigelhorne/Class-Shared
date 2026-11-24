use strict;
use warnings;

use Test::More;
use File::Temp qw(tempdir);
use lib 't/lib';

use Class::Shared::Frontend;

# Everything else in the suite shares Shared::Counter, which the backend has
# never heard of either, but this one shares a real module: the backend has to
# load Lingua::Conjunction from the installed tree and run its code.
plan skip_all => 'Lingua::Conjunction is not installed'
	unless eval { require Lingua::Conjunction; 1 };

my $dir = tempdir(CLEANUP => 1);

my $english = Class::Shared::Frontend->new(
	'Shared::Conjunction',
	ctor => [lang => 'en'],
	dir  => $dir,
);

END {
	eval { $english->shared_shutdown } if $english && $english->shared_connected;
}

isnt($english->shared_pid, $$, 'the object was constructed in another process');
is($english->module_version, $Lingua::Conjunction::VERSION,
	'and the backend loaded the real Lingua::Conjunction');
is($english->lang, 'en', 'with the arguments the frontend passed');

is($english->conjunction('Jack', 'Jill', 'Spot'), 'Jack, Jill, and Spot',
	'conjunction() runs in the shared copy');
is($english->conjunction('Jack', 'Jill'), 'Jack and Jill', 'and handles two items');
is($english->conjunction('Jack'), 'Jack', 'and one');

# Lingua::Conjunction keeps its language in package state, so a second object
# with a different language is the interesting case.
my $spanish = Class::Shared::Frontend->new(
	'Shared::Conjunction',
	ctor => [lang => 'es'],
	dir  => $dir,
);

is($spanish->conjunction('Jack', 'Jill', 'Spot'), 'Jack, Jill, y Spot',
	'a second object gets its own language');
is($english->conjunction('Jack', 'Jill', 'Spot'), 'Jack, Jill, and Spot',
	'and the first object is unaffected');
is($spanish->shared_pid, $english->shared_pid, 'both objects live in the one backend');

my $status = `$^X -Ilib -It/lib bin/class-shared status --class Shared::Conjunction --dir $dir 2>&1`;
like($status, qr/2 object\(s\)/, 'the backend counts both objects') or diag $status;

done_testing();
