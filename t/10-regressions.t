use strict;
use warnings;

use Test::More;
use Class::Shared ();

# Regressions found by code review.  Like the rest of the suite these need a
# unix socket in a directory only its owner can write to.
BEGIN {
	eval { require Test::Permissions; 1 }
		or plan skip_all => 'Test::Permissions is needed to say whether a '
			. 'directory can really be made owner-only, and is not installed';

	plan skip_all => 'a backend needs unix sockets in an owner-only directory, '
		. 'which this perl cannot provide (Class::Shared is Unix-only)'
		unless Class::Shared::_has_unix_sockets()
			&& Test::Permissions::can_revoke_create();
}

use File::Temp qw(tempdir);
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

$counter->shared_shutdown;

ok(!-e $counter->shared_socket_path || !-S $counter->shared_socket_path,
	'the backend that did own the socket still removes it when it stops');

done_testing();
