use strict;
use warnings;

use Test::More;
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

chomp(my $path = `$cli path --class Shared::Counter --dir $dir 2>&1`);
is($?, 0, 'path exits successfully') or diag $path;
is($path, $frontend->shared_socket_path, 'path prints the socket in use');

my $status = `$cli status --class Shared::Counter --dir $dir 2>&1`;
is($?, 0, 'status exits successfully') or diag $status;
like($status, qr/Shared::Counter: pid \d+/, 'status names the class and the backend pid');
like($status, qr/\d+ object\(s\)/, 'status counts the objects');
like($status, qr/address: .*\.sock/, 'status names the address');

my $token_file = "$dir/token";
open(my $token_fh, '>', $token_file) or die "cannot write $token_file: $!";
print {$token_fh} "s3cret\n";
close $token_fh;

my $tokenised = `$cli status --class Shared::Counter --dir $dir --token-file $token_file 2>&1`;
isnt($?, 0, 'status refuses a token on a unix socket');
like($tokenised, qr/a unix socket needs no token/,
	'and says the 0600 socket already decides who may connect');

my $missing = `$cli status --class Shared::Absent --dir $dir 2>&1`;
isnt($?, 0, 'status fails when nothing serves the class');
like($missing, qr/no backend for Shared::Absent/, 'and says so');

my $stopped = `$cli stop --class Shared::Counter --dir $dir 2>&1`;
is($?, 0, 'stop exits successfully') or diag $stopped;
like($stopped, qr/stopped Shared::Counter/, 'stop says what it stopped');
ok(!-e $frontend->shared_socket_path, 'the socket is gone after stop');

my $help = `$cli help 2>&1`;
is($?, 0, 'help exits successfully');
like($help, qr/usage: class-shared/, 'help explains itself');

done_testing();
