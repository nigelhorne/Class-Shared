use strict;
use warnings;

use Test::More;

# The commands talk to a backend over a unix socket in an owner-only directory,
# which Win32 does not have.
BEGIN {
	plan skip_all => 'the command line admin talks to a backend over a unix '
		. "socket, which MSWin32 does not have"
		if $^O eq 'MSWin32';
}

use File::Temp qw(tempdir);
use lib 't/lib';

use Class::Shared::Frontend;

my $dir = tempdir(CLEANUP => 1);

my $frontend = Class::Shared::Frontend->new(
	'Shared::Counter',
	ctor => [start => 3],
	dir  => $dir,
);

END {
	eval { $frontend->shared_shutdown } if $frontend && $frontend->shared_connected;
}

my $cli = "$^X -Ilib -It/lib bin/class-shared";

chomp(my $path = `$cli path --dir $dir 2>&1`);
is($?, 0, 'path exits successfully') or diag $path;
is($path, $frontend->shared_socket_path, 'path prints the socket in use');

my $status = `$cli status --dir $dir 2>&1`;
is($?, 0, 'status exits successfully') or diag $status;
like($status, qr/^pid \d+/m, 'status names the backend pid');
like($status, qr/^classes: Shared::Counter$/m, 'and the class it has loaded');
like($status, qr/\d+ object\(s\)/, 'status counts the objects');
like($status, qr/address: .*\.sock/, 'status names the address');

my $token_file = "$dir/token";
open(my $token_fh, '>', $token_file) or die "cannot write $token_file: $!";
print {$token_fh} "s3cret\n";
close $token_fh;

my $tokenised = `$cli status --dir $dir --token-file $token_file 2>&1`;
isnt($?, 0, 'status refuses a token on a unix socket');
like($tokenised, qr/a unix socket needs no token/,
	'and says the 0600 socket already decides who may connect');

# The class is loaded when a client asks for it, so asking for one that is not
# installed fails at the handshake, with the module named.
my $missing = `$^X -Ilib -It/lib -MClass::Shared::Frontend -e '
	Class::Shared::Frontend->new("Shared::Absent", dir => shift, autostart => 0)
		->shared_connect' $dir 2>&1`;
isnt($?, 0, 'a frontend whose class cannot be loaded fails');
like($missing, qr/cannot load Shared::Absent/, 'and names the module it could not load');

my $stopped = `$cli stop --dir $dir 2>&1`;
is($?, 0, 'stop exits successfully') or diag $stopped;
like($stopped, qr/^stopped$/m, 'stop says it stopped');
ok(!-e $frontend->shared_socket_path, 'the socket is gone after stop');

my $help = `$cli help 2>&1`;
is($?, 0, 'help exits successfully');
like($help, qr/usage: class-shared/, 'help explains itself');

done_testing();
