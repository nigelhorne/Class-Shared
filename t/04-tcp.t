use strict;
use warnings;

use Test::More;
use File::Spec ();
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Time::HiRes ();
use POSIX ();
use lib 't/lib';

BEGIN {
	eval { require IO::Socket::SSL; 1 }
		or plan skip_all => 'IO::Socket::SSL is required for the TCP tests';
}

use Net::SSLeay ();

use Class::Shared ();
use Class::Shared::Frontend;
use Class::Shared::Protocol;

# Fixtures from t/certs; see t/certs/make-certs.sh.  The server certificates
# name localhost and 127.0.0.1, because the tests connect to that address and
# the hostname is checked along with the chain.
my $certs = File::Spec->catdir('t', 'certs');
my %pem = map { $_ => File::Spec->catfile($certs, "$_.pem") }
	qw(ca server server-key client client-key other-ca other-client other-client-key
	other-server);

# The SHA-256 digest of a certificate, which is what a pin is.
sub fingerprint {
	my ($pem) = @_;

	my $bio = Net::SSLeay::BIO_new_file($pem, 'r') or return undef;
	my $cert = Net::SSLeay::PEM_read_bio_X509($bio) or return undef;
	Net::SSLeay::BIO_free($bio);
	my $digest = Net::SSLeay::EVP_get_digestbyname('sha256') or return undef;

	return unpack('H*', Net::SSLeay::X509_digest($cert, $digest));
}

my $dir = tempdir(CLEANUP => 1);

# Take a free port by opening one and letting it go again.
my $probe = IO::Socket::INET->new(
	LocalAddr => '127.0.0.1',
	LocalPort => 0,
	Proto     => 'tcp',
	Listen    => 1,
	ReuseAddr => 1,
) or plan skip_all => "cannot open a listening TCP socket: $!";

my $port = $probe->sockport;
close $probe;

my $token_file = File::Spec->catfile($dir, 'token');
open(my $token_fh, '>', $token_file) or plan skip_all => "cannot write $token_file: $!";
print {$token_fh} "s3cret-token\n";
close $token_fh;

my $tls = "--tls-cert $pem{server} --tls-key $pem{'server-key'} --tls-ca $pem{ca}";
my $base = "$^X -Ilib -It/lib bin/class-shared serve --class Shared::Counter "
	. "--listen tcp:127.0.0.1:$port --dir $dir -f";

# A port anybody can route to must not be a port where a stranger's bytes reach
# Storable::thaw, and must not be a port where they are readable either, so a
# TCP listener needs both a token and TLS, and refuses to start without either.
my $tokenless = `$base $tls 2>&1`;
isnt($?, 0, 'a TCP listener with no token refuses to start');
like($tokenless, qr/needs a token/, 'and says that a token is required');

my $plaintext = `$base --token-file $token_file 2>&1`;
isnt($?, 0, 'a TCP listener with no TLS refuses to start');
like($plaintext, qr/needs --tls-cert, --tls-key and --tls-ca/,
	'and says which TLS files it needs');

my $still_closed = IO::Socket::INET->new(
	PeerAddr => '127.0.0.1',
	PeerPort => $port,
	Proto    => 'tcp',
	Timeout  => 1,
);
ok(!$still_closed, 'and left nothing listening on the port');
close $still_closed if $still_closed;

my $pid = fork;
if (!defined $pid) {
	plan skip_all => "cannot fork: $!";
}

if ($pid == 0) {
	no warnings 'exec';    # exec() does not return when it works
	exec(
		$^X, '-Ilib', '-It/lib', 'bin/class-shared', 'serve',
		'--class', 'Shared::Counter',
		'--listen', "tcp:127.0.0.1:$port",
		'--token-file', $token_file,
		'--tls-cert', $pem{server},
		'--tls-key', $pem{'server-key'},
		'--tls-ca', $pem{ca},
		'--dir', $dir,
		'-f',
	);
	POSIX::_exit(127);
}

END {
	kill 'TERM', $pid if $pid && kill(0, $pid);
}

# A frontend with the certificate and CA a working client uses.
sub frontend {
	my (%override) = @_;

	my %opt = (
		host       => '127.0.0.1',
		port       => $port,
		token_file => $token_file,
		tls_ca     => $pem{ca},
		tls_cert   => $pem{client},
		tls_key    => $pem{'client-key'},
	);

	for my $key (keys %override) {
		if (defined $override{$key}) {
			$opt{$key} = $override{$key};
		} else {
			delete $opt{$key};
		}
	}

	return Class::Shared::Frontend->new('Shared::Counter', %opt);
}

my $ready = 0;
for (1 .. 200) {
	my $probe_socket = eval { frontend() };
	if ($probe_socket) {
		$probe_socket->shared_close;
		$ready = 1;
		last;
	}
	select(undef, undef, undef, 0.05);
}

ok($ready, 'the TLS backend came up and a verified client reached it')
	or BAIL_OUT('no backend to test against');

my $frontend = frontend(ctor => [start => 5]);

is($frontend->shared_pid, $pid, 'the frontend talks to the backend we started');
is($frontend->shared_address, "127.0.0.1:$port", 'it knows the address');
is($frontend->value, 5, 'the object was constructed in the backend');
is($frontend->inc, 6, 'a call works over TLS');

my $second = frontend(ctor => [start => 1]);

isnt($second->shared_id, $frontend->shared_id, 'a second client gets its own object');
is($second->value, 1, 'with its own state');
is($frontend->value, 6, 'and neither disturbs the other');
is($second->shared_pid, $frontend->shared_pid, 'both objects share the one backend');

# Verification.  A client that cannot verify the backend, or that the backend
# cannot verify, has to end up with nothing, not with a connection it believes
# in.
my $constructed = $frontend->shared_status->{constructed};

my @refused = (
	[
		'a CA that did not sign the backend',
		{ tls_ca => $pem{'other-ca'} },
		qr/certificate verify|verify|TLS/i,
	],
	[
		'a certificate from a CA the backend does not trust',
		{ tls_cert => $pem{'other-client'}, tls_key => $pem{'other-client-key'} },
		qr/refused this client's certificate.*tls_cert.*tls_ca/s,
	],
);

for my $case (@refused) {
	my ($label, $override, $expected) = @{$case};

	my $object = eval { frontend(%{$override}) };

	ok(!defined $object, "a client with $label gets no object");
	like($@, $expected, 'and is told why');
}

is($frontend->shared_status->{constructed}, $constructed,
	'and the backend constructed nothing for either of them');

# A pin is the other way to verify: the same certificate, named by its digest
# instead of by who signed it, so no CA file is involved at all.
my $server_fp = fingerprint($pem{server});
my $other_fp  = fingerprint($pem{'other-server'});

ok(defined $server_fp && $server_fp =~ /\A[0-9a-f]{64}\z/,
	'the backend certificate has a SHA-256 fingerprint');

is(Class::Shared::normalise_fingerprint(uc join(':', $server_fp =~ /../g)),
	"sha256\$$server_fp",
	'a fingerprint in the form openssl prints is normalised for the TLS layer');

my $pinned = eval {
	frontend(tls_ca => undef, tls_fingerprint => join(':', $server_fp =~ /../g),
		ctor => [start => 7]);
};
ok($pinned, 'a pinned fingerprint connects with no CA file') or diag $@;
is($pinned->value, 7, 'and the pinned object works') if $pinned;
$pinned->shared_close if $pinned;

my $wrong_pin = eval { frontend(tls_ca => undef, tls_fingerprint => $other_fp) };
ok(!defined $wrong_pin, 'a pin the backend does not match gets no object');
like($@, qr/certificate verify|TLS/i, 'and is told the certificate did not verify');

my $both = eval { frontend(tls_fingerprint => $server_fp) };
ok(!defined $both, 'a CA and a pin together are refused');
like($@, qr/not both/, 'because they are alternatives');

my $neither = eval { frontend(tls_ca => undef) };
ok(!defined $neither, 'a TCP frontend with neither a CA nor a pin is refused');
like($@, qr/tls_ca or tls_fingerprint/, 'and says verification needs one of them');

is($frontend->shared_status->{constructed}, $constructed + 1,
	'and only the pin that matched the backend constructed anything');

# The object the pinned client built is real, so it is the new baseline.
$constructed = $frontend->shared_status->{constructed};

# The token still has to be right once TLS is established: the two are separate
# checks, and either one alone is not the whole answer.
my $no_token = eval { frontend(token_file => undef) };
ok(!defined $no_token, 'a TLS client without the token gets no object');
like($@, qr/may require a token|failed authentication/, 'and is told why');

my $wrong_token = eval { frontend(token => 'not-the-token', token_file => undef) };
ok(!defined $wrong_token, 'a TLS client with the wrong token gets no object');
like($@, qr/failed authentication/, 'and is told that its frames do not authenticate');

is($frontend->shared_status->{constructed}, $constructed,
	'and neither of those reached the constructor either');

# A client with no certificate at all may finish its own side of a TLS 1.3
# handshake before the backend's refusal arrives, but it never gets a reply.
my $certless = IO::Socket::SSL->new(
	PeerAddr        => '127.0.0.1',
	PeerPort        => $port,
	Proto           => 'tcp',
	Timeout         => 5,
	SSL_ca_file     => $pem{ca},
	SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
);

if ($certless) {
	my ($hello) = Class::Shared::Protocol::encode_frame({
		op    => 'hello',
		proto => $Class::Shared::PROTOCOL_VERSION,
		class => 'Shared::Counter',
	}, 's3cret-token');

	Class::Shared::Protocol::write_all($certless, $hello);

	my ($reply, $read_error) = Class::Shared::Protocol::read_frame($certless, 5, 's3cret-token');
	is($reply, undef, 'a client with no certificate gets no reply');
	like($read_error, qr/closed|read failed|exceeds the limit/i,
		'because the backend dropped it without a frame');

	close $certless;
} else {
	pass('a client with no certificate cannot even connect')
		for 1 .. 1;
	pass('and so gets no reply') for 1 .. 1;
}

# A frame this backend cannot authenticate must be refused before it is thawed.
# The bodies below are valid Storable images, so the digest is the only thing
# between them and the backend's interpreter.
my @forged = (
	[
		'signed with the wrong secret',
		(Class::Shared::Protocol::encode_frame({
			op    => 'hello',
			proto => $Class::Shared::PROTOCOL_VERSION,
			class => 'Shared::Counter',
		}, 'not-the-token'))[0],
	],
	[
		'with no digest at all',
		(Class::Shared::Protocol::encode_frame({
			op    => 'hello',
			proto => $Class::Shared::PROTOCOL_VERSION,
			class => 'Shared::Counter',
		}))[0],
	],
);

for my $case (@forged) {
	my ($label, $frame) = @{$case};

	ok(defined $frame, "a frame $label is built") or next;

	my $raw = IO::Socket::SSL->new(
		PeerAddr        => '127.0.0.1',
		PeerPort        => $port,
		Proto           => 'tcp',
		Timeout         => 5,
		SSL_ca_file     => $pem{ca},
		SSL_cert_file   => $pem{client},
		SSL_key_file    => $pem{'client-key'},
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
	) or BAIL_OUT('cannot open a verified TLS connection to the backend');

	my ($sent) = Class::Shared::Protocol::write_all($raw, $frame);
	ok($sent, 'and sent to the backend');

	my ($reply, $read_error) = Class::Shared::Protocol::read_frame($raw, 5, 's3cret-token');
	ok(defined $reply, 'the backend answers') or diag $read_error;
	next unless $reply;

	ok(!$reply->{ok}, "the frame $label is refused");
	like($reply->{error}, qr/failed authentication|too short/,
		'because it could not be authenticated');

	# The connection is dropped rather than kept for another guess.
	my ($after, $after_error) = Class::Shared::Protocol::read_frame($raw, 5, 's3cret-token');
	is($after, undef, 'and the connection is closed');
	like($after_error, qr/closed|read failed/i, 'as a closed stream');

	close $raw;
}

is($frontend->value, 6, 'the real client still works after the forgeries');

# Plaintext never reaches the frame parser: the listener is the TLS endpoint, so
# a hello sent in the clear is not a message, it is a protocol violation.
my $plain = IO::Socket::INET->new(
	PeerAddr => '127.0.0.1',
	PeerPort => $port,
	Proto    => 'tcp',
	Timeout  => 5,
) or BAIL_OUT("cannot open a plain connection to the backend: $!");

my ($plain_hello) = Class::Shared::Protocol::encode_frame({
	op    => 'hello',
	proto => $Class::Shared::PROTOCOL_VERSION,
	class => 'Shared::Counter',
}, 's3cret-token');

Class::Shared::Protocol::write_all($plain, $plain_hello);

my ($plain_reply, $plain_error) = Class::Shared::Protocol::read_frame($plain, 5, 's3cret-token');
is($plain_reply, undef, 'a plaintext frame gets no reply');
like($plain_error, qr/closed|read failed|reset|exceeds the limit/i,
	'and nothing Storable comes back');
close $plain;

is($frontend->shared_status->{constructed}, $constructed,
	'and none of those attempts constructed an object');

# A connection that opens and then says nothing must not stall the backend:
# the handshake is carried on from the select loop, not inside accept().
my @silent;
for (1 .. 3) {
	my $quiet = IO::Socket::INET->new(
		PeerAddr => '127.0.0.1',
		PeerPort => $port,
		Proto    => 'tcp',
		Timeout  => 5,
	) or BAIL_OUT("cannot open a silent connection: $!");
	push @silent, $quiet;
}

# Let the backend accept them and start handshakes that will never finish, so
# the real client below is the one that has to wait if the loop is blocked.
select(undef, undef, undef, 0.3);

my $started = Time::HiRes::time();
my $during = eval { frontend(ctor => [start => 11]) };
my $elapsed = Time::HiRes::time() - $started;

ok($during, 'a real client connects while silent clients are mid-handshake')
	or diag $@;
is($during->value, 11, 'and its object works') if $during;
cmp_ok($elapsed, '<', 3,
	"and is served at once, not after a handshake timeout ($elapsed s)");
$during->shared_close if $during;

close $_ for @silent;

# The handshake deadline is a constructor option, so a backend with a short one
# can be started here: a client that connects and says nothing has to lose its
# slot when its time is up, and the real client has to keep working.
my $deadline_probe = IO::Socket::INET->new(
	LocalAddr => '127.0.0.1',
	LocalPort => 0,
	Proto     => 'tcp',
	Listen    => 1,
	ReuseAddr => 1,
) or BAIL_OUT("cannot reserve a port for the deadline backend: $!");
my $deadline_port = $deadline_probe->sockport;
close $deadline_probe;

my $deadline_dir = File::Spec->catdir($dir, 'deadline');

my $short_pid = fork;
BAIL_OUT("cannot fork: $!") unless defined $short_pid;

if (!$short_pid) {
	no warnings 'exec';    # exec() does not return when it works
	exec(
		$^X, '-Ilib', '-It/lib', '-MClass::Shared::Backend', '-e',
		'Class::Shared::Backend->new(' . join(', ',
			'class => shift', 'host => shift', 'port => shift',
			'token => shift', 'tls_cert => shift', 'tls_key => shift',
			'tls_ca => shift', 'dir => shift', 'log => shift',
			'handshake_timeout => shift') . ')->run()',
		'Shared::Counter', '127.0.0.1', $deadline_port, 's3cret-token',
		$pem{server}, $pem{'server-key'}, $pem{ca},
		$deadline_dir, File::Spec->catfile($deadline_dir, 'log'), 1,
	);
	POSIX::_exit(127);
}

END {
	kill 'TERM', $short_pid if $short_pid && kill(0, $short_pid);
}

my $real;
for (1 .. 100) {
	$real = eval { frontend(port => $deadline_port, ctor => [start => 3]) };
	last if $real;
	select(undef, undef, undef, 0.05);
}

ok($real, 'a backend with a short handshake deadline came up') or diag $@;

if ($real) {
	is($real->value, 3, 'the real client has its object');

	my $baseline = $real->shared_status->{clients};

	my $lonely = IO::Socket::INET->new(
		PeerAddr => '127.0.0.1',
		PeerPort => $deadline_port,
		Proto    => 'tcp',
		Timeout  => 5,
	) or BAIL_OUT("cannot open a silent connection: $!");

	my $holding = 0;
	for (1 .. 40) {
		if ($real->shared_status->{clients} > $baseline) {
			$holding = 1;
			last;
		}
		select(undef, undef, undef, 0.05);
	}
	ok($holding, 'a silent client holds a slot while its handshake is pending');

	my $freed = 0;
	for (1 .. 60) {
		if ($real->shared_status->{clients} <= $baseline) {
			$freed = 1;
			last;
		}
		select(undef, undef, undef, 0.1);
	}
	ok($freed, 'and loses it once its handshake deadline passes');

	is($real->value, 3, 'while the real client carries on working');

	close $lonely;

	ok($real->shared_shutdown, 'the deadline backend can be stopped');
	waitpid($short_pid, 0);
	is($?, 0, 'and it exited cleanly');
	undef $short_pid;
}

# Nothing can be autostarted over TCP: a closed port is an error.
my $closed = IO::Socket::INET->new(
	LocalAddr => '127.0.0.1',
	LocalPort => 0,
	Proto     => 'tcp',
	Listen    => 1,
	ReuseAddr => 1,
);
my $closed_port = $closed->sockport;
close $closed;

eval {
	frontend(port => $closed_port);
};
like($@, qr/cannot reach a backend/, 'a closed TCP endpoint is an error, not a spawn');

ok($frontend->shared_shutdown, 'the TCP backend can be stopped');
waitpid($pid, 0);
is($?, 0, 'and it exited cleanly');

undef $pid;

done_testing();
