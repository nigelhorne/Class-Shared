package Class::Shared::Backend;

use strict;
use warnings;

use Fcntl qw(:flock F_SETFD FD_CLOEXEC O_RDWR O_CREAT);
use File::Spec ();
use IO::Socket::INET;
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

use Class::Shared ();
use Class::Shared::Protocol ();

our $VERSION = '0.01';

our $DEFAULT_MAX_CLIENTS = 512;
our $DEFAULT_MAX_OBJECTS = 4096;

# How long a connection may spend on its TLS handshake.  The handshake is done
# a little at a time from the select loop, so a peer that connects and then
# says nothing costs one connection slot for this long, not the whole backend.
our $HANDSHAKE_TIMEOUT = 5;

# The backend loads one class, once, and holds many objects made from it: one
# per frontend.  Clients talk to it over a unix socket or TCP.
sub new {
	my ($class, %opt) = @_;

	my $target = $opt{class};
	die "Class::Shared::Backend->new: no class => given\n"
		unless defined $target && length $target;

	Class::Shared::validate_class($target);

	my ($host, $port, $socket) = @opt{qw(host port socket)};

	if (defined $host || defined $port) {
		die "Class::Shared::Backend->new: a TCP listener needs both host and port\n"
			unless defined $host && defined $port;
		die "Class::Shared::Backend->new: use either socket or host/port, not both\n"
			if defined $socket;

		# A TCP port is reachable by anybody who can route to it, and thawing
		# is running code, so refuse to be the listener that would deserialise
		# whatever a stranger sends.
		my $token = $opt{token};
		die "Class::Shared::Backend->new: a TCP listener needs a token: "
			. "without one it would thaw whatever arrives\n"
			unless defined $token && length $token;

		# TLS is not a wrapper here but the listener itself: this certificate
		# proves who the backend is, tls_ca decides which client certificates
		# are welcome, and a client without one is never accepted.
		die "Class::Shared::Backend->new: a TCP listener needs tls_cert, "
			. "tls_key and tls_ca: without them the traffic would be readable "
			. "to anyone who can route to it\n"
			if grep { !defined $opt{$_} || !length $opt{$_} } qw(tls_cert tls_key tls_ca);
	} else {
		$socket = Class::Shared::socket_path($target, $opt{dir})
			unless defined $socket;

		# The socket is mode 0600 in a directory only its owner can write to,
		# so the kernel has already decided who may connect: a digest on every
		# frame would buy nothing here and cost 32 bytes on each message.
		die "Class::Shared::Backend->new: a unix socket needs no token: "
			. "its mode 0600 file already decides who may connect\n"
			if defined $opt{token} && length $opt{token};

		die "Class::Shared::Backend->new: a unix socket needs no TLS: "
			. "its mode 0600 file already decides who may connect\n"
			if grep { defined $opt{$_} && length $opt{$_} } qw(tls_cert tls_key tls_ca);
	}

	my $control = defined $socket
		? $socket
		: Class::Shared::socket_path($target, $opt{dir});

	my $self = bless {
		class         => $target,
		socket        => $socket,
		host          => $host,
		port          => $port,
		token         => $opt{token},
		tls_cert      => $opt{tls_cert},
		tls_key       => $opt{tls_key},
		tls_ca        => $opt{tls_ca},
		dir_hint      => $opt{dir},
		control       => $control,
		log           => $opt{log} || ($control . '.log'),
		daemonize     => $opt{daemonize} ? 1 : 0,
					max_clients   => $opt{max_clients} || $DEFAULT_MAX_CLIENTS,
			max_objects   => $opt{max_objects} || $DEFAULT_MAX_OBJECTS,
			handshake_timeout => defined $opt{handshake_timeout}
				? $opt{handshake_timeout}
				: $HANDSHAKE_TIMEOUT,
		start_timeout => defined $opt{start_timeout} ? $opt{start_timeout} : 2,
		objects       => {},
		clients       => {},
		next_id       => 1,
		next_serial   => 1,
		calls         => 0,
		constructed   => 0,
		started       => time,
		stop          => 0,
		cleaned       => 0,
		logfh         => undef,
		listener      => undef,
		lock          => undef,
		address       => undef,
	}, $class;

	return $self;
}

sub run {
	my $self = shift;

	my $loaded = eval { $self->_load_class; 1 };
	if (!$loaded) {
		my $error = $@ || 'unknown error';
		$self->_log("fatal: $error");
		die $error;
	}

	$self->_daemonize if $self->{daemonize};

	my $started = eval { $self->_setup; 1 };
	if (!$started) {
		my $error = $@ || 'unknown error';
		$self->_log("fatal: $error");
		die $error unless $self->{daemonize};
		exit 1;
	}

	$self->_log("serving $self->{class} on $self->{address} (pid $$"
		. ($self->{token} ? ', token required' : '')
		. (defined $self->{host} ? ', TLS with client certificates' : '') . ')');

	$self->_loop;
	$self->_cleanup;

	$self->_log('stopped');

	return 0;
}

sub DESTROY {
	my $self = shift;
	return if $self->{cleaned};
	$self->{cleaned} = 1;
	unlink $self->{socket} if $self->{socket} && -e $self->{socket};
}

sub _load_class {
	my $self = shift;

	my $file = $self->{class};
	$file =~ s{::}{/}g;
	$file .= '.pm';

	eval { require $file; 1 }
		or die "cannot load $self->{class}: " . ($@ || 'unknown error');

	return 1;
}

sub _setup {
	my $self = shift;

	# The lock, the pid file and the default log live beside the control path,
	# so that is the only directory this backend needs.
	my $dir = Class::Shared::dir_of($self->{control});

	my ($dir_ok, $dir_error) = Class::Shared::ensure_dir($dir);
	die "$dir_error\n" unless $dir_ok;

	my $lock_path = $self->{control} . '.owner';
	my $lock;
	sysopen($lock, $lock_path, O_RDWR | O_CREAT, 0600)
		or die "cannot open $lock_path: $!\n";

	# A backend that is shutting down still holds the lock for a moment, so
	# give it a short while before deciding that somebody else is serving.
	my $deadline = time + $self->{start_timeout};
	while (1) {
		last if flock($lock, LOCK_EX | LOCK_NB);
		if (time >= $deadline) {
			die "another backend is already serving $self->{class} ($lock_path is locked)\n";
		}
		select(undef, undef, undef, 0.02);
	}
	$self->{lock} = $lock;

	if (defined $self->{socket}) {
		$self->_setup_unix;
	} else {
		$self->_setup_tcp;
	}

	fcntl($self->{listener}, F_SETFD, FD_CLOEXEC);

	my $pid_path = $self->{control} . '.pid';
	if (open(my $pid_fh, '>', $pid_path)) {
		print {$pid_fh} "$$\n";
		close $pid_fh;
	}

	return 1;
}

sub _setup_unix {
	my $self = shift;

	if (-e $self->{socket}) {
		my $probe = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $self->{socket});
		if ($probe) {
			close $probe;
			die "a backend is already listening on $self->{socket}\n";
		}
		unlink $self->{socket}
			or die "cannot remove the stale socket $self->{socket}: $!\n";
	}

	my $listener = IO::Socket::UNIX->new(
		Type     => SOCK_STREAM,
		Local    => $self->{socket},
		Listen   => 64,
		Blocking => 1,
	) or die "cannot listen on $self->{socket}: $!\n";

	chmod 0600, $self->{socket}
		or die "cannot set permissions on $self->{socket}: $!\n";

	$self->{listener} = $listener;
	$self->{address} = $self->{socket};

	return 1;
}

sub _setup_tcp {
	my $self = shift;

	die "Class::Shared::Backend: no TCP address configured\n"
		unless defined $self->{host} && defined $self->{port};

	# Loaded only for a TCP listener: a unix socket never pays for TLS, just
	# as it never paid for the digest.
	require IO::Socket::SSL;

	# One context for every connection: the certificates are read and checked
	# once, and each accepted socket starts its handshake against it.
	my $context = IO::Socket::SSL::SSL_Context->new(
		SSL_server      => 1,
		SSL_cert_file   => $self->{tls_cert},
		SSL_key_file    => $self->{tls_key},
		SSL_ca_file     => $self->{tls_ca},
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER()
			| IO::Socket::SSL::SSL_VERIFY_FAIL_IF_NO_PEER_CERT(),
	) or die "cannot set up TLS for $self->{host}:$self->{port}: "
		. (IO::Socket::SSL::errstr() || "$!" || 'unknown error') . "\n";

	$self->{tls_context} = $context;

	# The listener is plain TCP.  The handshake belongs to the connection, where
	# it can be carried a little at a time as that connection becomes ready; in
	# accept() it would stall every client already being served for as long as
	# the newest one stayed silent.
	my $listener = IO::Socket::INET->new(
		LocalAddr => $self->{host},
		LocalPort => $self->{port},
		Proto     => 'tcp',
		Listen    => 64,
		ReuseAddr => 1,
	) or die "cannot listen on $self->{host}:$self->{port}: $!\n";

	$self->{listener} = $listener;
	$self->{address} = $self->{host} . ':' . $self->{port};

	return 1;
}

sub _loop {
	my $self = shift;

	local $SIG{TERM} = sub { $self->{stop} = 1 };
	local $SIG{INT}  = sub { $self->{stop} = 1 };
	local $SIG{HUP}  = 'IGNORE';
	local $SIG{PIPE} = 'IGNORE';

	while (!$self->{stop}) {
		my $rin = '';
		my $win = '';
		my $handshaking = 0;

		vec($rin, fileno($self->{listener}), 1) = 1;

		for my $client (values %{$self->{clients}}) {
			my $fd = fileno($client->{fh});
			next unless defined $fd;

			vec($rin, $fd, 1) = 1;

			next unless $client->{handshaking};
			$handshaking = 1;

			# A handshake can want to write as well (TLS 1.3 tickets, a full
			# send buffer), so wait for that only when it asked for it.
			vec($win, $fd, 1) = 1 if $client->{want_write};
		}

		# With a handshake in progress, wake up now and then: a peer that
		# never speaks would otherwise keep select asleep past its deadline.
		my $ready = select(my $rout = $rin, my $wout = $win, undef,
			$handshaking ? 0.25 : undef);

		$self->_expire_handshakes if $handshaking;

		next if !defined $ready || $ready <= 0;

		if (vec($rout, fileno($self->{listener}), 1)) {
			$self->_accept;
		}

		for my $key (keys %{$self->{clients}}) {
			my $client = $self->{clients}{$key};
			next unless $client;

			my $fd = fileno($client->{fh});
			next unless defined $fd;

			if ($client->{handshaking}) {
				next unless vec($rout, $fd, 1)
					|| ($client->{want_write} && vec($wout, $fd, 1));
				$self->_continue_tls($client);
			} else {
				next unless vec($rout, $fd, 1);
				$self->_serve_client($client);
			}

			last if $self->{stop};
		}
	}

	return 1;
}

# Drop connections whose handshake has run out of time, so a peer that opens a
# socket and then says nothing frees its slot again.
sub _expire_handshakes {
	my $self = shift;

	my $now = time;

	for my $client (values %{$self->{clients}}) {
		next unless $client->{handshaking};
		next if $client->{deadline} > $now;

		$self->_drop_client($client, 'TLS handshake timed out');
	}

	return 1;
}

sub _accept {
	my $self = shift;

	my $fh = $self->{listener}->accept;
	return unless $fh;

	if (keys %{$self->{clients}} >= $self->{max_clients}) {
		# A unix client can be told, signed like every other frame.  A TCP
		# client has not handshaken yet, so there is no session to sign one
		# for: it is closed, and the frontend reports a failed connection.
		if (!defined $self->{host}) {
			my ($bytes) = Class::Shared::Protocol::encode_frame({
				ok    => 0,
				kind  => 'busy',
				error => "backend is serving too many clients ($self->{max_clients})",
			}, $self->{token});
			Class::Shared::Protocol::write_all($fh, $bytes) if defined $bytes;
		}

		close $fh;
		return;
	}

	fcntl($fh, F_SETFD, FD_CLOEXEC);

	my $client = {
		fh      => $fh,
		buffer  => '',
		greeted => 0,
		serial  => $self->{next_serial}++,
		objects => {},
	};

	if (defined $self->{host}) {
		my $ssl = $self->_start_tls($fh);

		if (!$ssl) {
			$self->_log('refused a TLS connection: '
				. (IO::Socket::SSL::errstr() || 'cannot start a handshake'));
			close $fh;
			return;
		}

		$client->{fh}          = $ssl;
		$client->{handshaking} = 1;
		$client->{want_write}  = 0;
		$client->{deadline}    = time + $self->{handshake_timeout};
	}

	$self->{clients}{ fileno($client->{fh}) } = $client;

	return 1;
}

# Give an accepted socket its TLS layer but do not perform the handshake here:
# accept_SSL() is called from the select loop as the socket becomes ready, so a
# silent peer holds one pending handshake instead of the whole backend.
sub _start_tls {
	my ($self, $fh) = @_;

	$fh->blocking(0);

	return IO::Socket::SSL->start_SSL(
		$fh,
		SSL_server         => 1,
		SSL_startHandshake => 0,
		SSL_reuse_ctx      => $self->{tls_context},
	);
}

# One step of a pending handshake.  Returns nothing; the client either becomes
# an ordinary connection, waits for the next readiness, or is dropped.
sub _continue_tls {
	my ($self, $client) = @_;

	my $fh = $client->{fh};

	if ($fh->accept_SSL) {
		$client->{handshaking} = 0;
		$client->{want_write}  = 0;
		delete $client->{deadline};

		# Frame handling is written for a blocking socket: only the
		# handshake needed to be incremental.
		$fh->blocking(1);

		return 1;
	}

	# A failed handshake reblesses the socket back to the plain class it was
	# upgraded from, so the handle can no longer answer TLS questions.  Ask
	# the TLS layer for the last error instead.
	my $error = do { no warnings 'once'; $IO::Socket::SSL::SSL_ERROR };

	if (defined $error && $error == IO::Socket::SSL::SSL_WANT_READ()) {
		$client->{want_write} = 0;
		return 1;
	}

	if (defined $error && $error == IO::Socket::SSL::SSL_WANT_WRITE()) {
		$client->{want_write} = 1;
		return 1;
	}

	$self->_log('refused a TLS connection: '
		. (IO::Socket::SSL::errstr() || 'handshake failed'));
	$self->_drop_client($client, 'TLS handshake failed');

	return;
}

sub _serve_client {
	my ($self, $client) = @_;

	my $read = sysread($client->{fh}, my $chunk, 65536);

	if (!defined $read) {
		$self->_drop_client($client, "read error: $!");
		return;
	}

	if ($read == 0) {
		$self->_drop_client($client, 'client disconnected');
		return;
	}

	$client->{buffer} .= $chunk;

	while (1) {
		# With a token, take_frame checks the frame's digest before it
		# thaws anything, so an unauthenticated peer never gets as far as
		# Storable.
		my ($status, $message, $protocol_error)
			= Class::Shared::Protocol::take_frame(\$client->{buffer}, $self->{token});

		if ($status == 0) {
			last;
		}

		if ($status < 0) {
			$self->_send($client, {
				ok    => 0,
				kind  => 'protocol',
				error => $protocol_error,
			});
			$self->_drop_client($client, $protocol_error);
			last;
		}

		my $response = eval { $self->_dispatch($client, $message) };
		if ($@) {
			my $internal = $@;
			$internal =~ s/\s+\z//;
			$self->_log("internal error while handling a request: $internal");
			$response = {
				ok    => 0,
				kind  => 'internal',
				error => $internal,
			};
		}

		$self->_send($client, $response) if defined $response;

		last if $self->{stop};
	}

	return 1;
}

# The connection owns its objects: when it goes, they go, and the target's
# DESTROY runs here rather than being lost with a dead client.
sub _drop_client {
	my ($self, $client, $reason) = @_;

	my $owned = $client->{objects} || {};
	for my $id (keys %{$owned}) {
		delete $self->{objects}{$id};
	}
	%{$owned} = ();

	my $fd = fileno($client->{fh});
	close $client->{fh};
	delete $self->{clients}{$fd} if defined $fd;

	return 1;
}

sub _send {
	my ($self, $client, $message) = @_;

	my ($bytes, $encode_error) = Class::Shared::Protocol::encode_frame($message, $self->{token});

	if (!defined $bytes) {
		my $error = $encode_error;
		($bytes) = Class::Shared::Protocol::encode_frame({
			ok    => 0,
			kind  => 'protocol',
			error => $error,
		}, $self->{token});
	}

	return unless defined $bytes;

	my ($ok, $write_error) = Class::Shared::Protocol::write_all($client->{fh}, $bytes);
	$self->_drop_client($client, $write_error) unless $ok;

	return $ok;
}

# ------------------------------------------------------------- request ops

sub _dispatch {
	my ($self, $client, $message) = @_;

	if (ref($message) ne 'HASH') {
		return { ok => 0, kind => 'protocol', error => 'request is not a hash reference' };
	}

	my $op = defined $message->{op} ? $message->{op} : '';

	if ($op eq 'hello') {
		return $self->_op_hello($client, $message);
	}

	if (!$client->{greeted}) {
		return { ok => 0, kind => 'protocol', error => 'handshake required' };
	}

	return $self->_op_new($client, $message) if $op eq 'new';
	return $self->_op_call($client, $message) if $op eq 'call';
	return $self->_op_ping                  if $op eq 'ping';
	return $self->_op_shutdown              if $op eq 'shutdown';

	return { ok => 0, kind => 'protocol', error => "unknown operation '$op'" };
}

sub _op_hello {
	my ($self, $client, $message) = @_;

	my $proto = defined $message->{proto} ? $message->{proto} : 0;

	if ($proto != $Class::Shared::PROTOCOL_VERSION) {
		return {
			ok    => 0,
			kind  => 'protocol',
			error => "protocol version mismatch: client speaks $proto, this backend speaks "
				. $Class::Shared::PROTOCOL_VERSION,
		};
	}

	my $wanted = defined $message->{class} ? $message->{class} : '';

	if ($wanted ne $self->{class}) {
		return {
			ok    => 0,
			kind  => 'protocol',
			error => "this backend serves $self->{class}, not '$wanted'",
		};
	}

	$client->{greeted} = 1;

	return {
		ok      => 1,
		class   => $self->{class},
		pid     => $$,
		proto   => $Class::Shared::PROTOCOL_VERSION,
		version => $Class::Shared::VERSION,
	};
}

sub _op_new {
	my ($self, $client, $message) = @_;

	my $args = $message->{args};
	$args = [] unless defined $args;

	return { ok => 0, kind => 'protocol', error => 'new: args must be an array reference' }
		unless ref($args) eq 'ARRAY';

	my $held = keys %{$self->{objects}};
	if ($held >= $self->{max_objects}) {
		return {
			ok    => 0,
			kind  => 'busy',
			error => "this backend already holds $held objects, its limit",
		};
	}

	my $object = eval { $self->{class}->new(@{$args}) };
	if ($@) {
		return { ok => 0, kind => 'die', error => "$@" };
	}

	return {
		ok    => 0,
		kind  => 'protocol',
		error => "$self->{class}->new did not return an object",
	} unless ref($object);

	my $id = $self->{next_id}++;

	$self->{objects}{$id} = {
		object => $object,
		owner  => $client->{serial},
	};
	$client->{objects}{$id} = 1;
	$self->{constructed}++;

	return { ok => 1, id => $id, class => $self->{class} };
}

sub _op_call {
	my ($self, $client, $message) = @_;

	my $id = $message->{id};
	return { ok => 0, kind => 'protocol', error => 'call: no object id' }
		unless defined $id && $id =~ /\A\d+\z/;

	my $entry = $self->{objects}{$id};
	return {
		ok    => 0,
		kind  => 'unknown_object',
		error => "no object #$id here; it may have been released or its client has gone",
	} unless $entry;

	return {
		ok    => 0,
		kind  => 'forbidden',
		error => "object #$id belongs to another connection",
	} unless $entry->{owner} == $client->{serial};

	my $object = $entry->{object};

	my $method = $message->{method};
	return { ok => 0, kind => 'protocol', error => 'call: no method name' }
		unless defined $method && length $method;

	my $args = $message->{args};
	$args = [] unless defined $args;
	return { ok => 0, kind => 'protocol', error => 'call: args must be an array reference' }
		unless ref($args) eq 'ARRAY';

	my $want = $message->{want};
	$want = 'scalar' unless defined $want;
	return { ok => 0, kind => 'protocol', error => "call: unknown calling context '$want'" }
		unless $want =~ /\A(?:list|scalar|void)\z/;

	if ($method eq 'new' or $method eq 'DESTROY' or $method eq 'AUTOLOAD') {
		return {
			ok    => 0,
			kind  => 'forbidden',
			error => "cannot call $method() through Class::Shared",
		};
	}

	# can() and isa() are answered locally as booleans: the code reference
	# that can() normally returns cannot cross the wire.
	if ($method eq 'can' or $method eq 'isa') {
		my $name = $args->[0];
		my $answer = eval { $object->$method($name) ? 1 : 0 };
		return { ok => 0, kind => 'die', error => "$@" } if $@;
		return { ok => 1, result => [$answer] };
	}

	if (!$self->{class}->can($method) && !$self->{class}->can('AUTOLOAD')) {
		return {
			ok    => 0,
			kind  => 'unknown_method',
			error => "$self->{class} has no method '$method'",
		};
	}

	my @result;
	my $ok = eval {
		if ($want eq 'list') {
			@result = $object->$method(@{$args});
		} elsif ($want eq 'void') {
			$object->$method(@{$args});
			@result = ();
		} else {
			my $scalar = $object->$method(@{$args});
			@result = ($scalar);
		}
		1;
	};

	if (!$ok) {
		return { ok => 0, kind => 'die', error => "$@" };
	}

	$self->{calls}++;

	return { ok => 1, result => [@result] };
}

sub _op_ping {
	my $self = shift;

	return {
		ok          => 1,
		class       => $self->{class},
		pid         => $$,
		proto       => $Class::Shared::PROTOCOL_VERSION,
		version     => $Class::Shared::VERSION,
		address     => $self->{address},
		calls       => $self->{calls},
		objects     => scalar(keys %{$self->{objects}}),
		constructed => $self->{constructed},
		clients     => scalar(keys %{$self->{clients}}),
		started     => $self->{started},
		uptime      => time - $self->{started},
	};
}

sub _op_shutdown {
	my $self = shift;

	$self->_log('shutdown requested');
	$self->{stop} = 1;

	return { ok => 1, message => 'shutting down' };
}

# ---------------------------------------------------------------- plumbing

sub _cleanup {
	my $self = shift;

	return if $self->{cleaned};
	$self->{cleaned} = 1;

	if ($self->{listener}) {
		close $self->{listener};
		$self->{listener} = undef;
	}

	unlink $self->{socket} if defined $self->{socket};

	for my $client (values %{$self->{clients}}) {
		close $client->{fh};
	}

	# Every object the backend still holds is destroyed here, once, in the
	# process that created them.
	%{$self->{objects}} = ();
	%{$self->{clients}} = ();

	unlink $self->{control} . '.pid';

	if ($self->{lock}) {
		flock($self->{lock}, LOCK_UN);
		close $self->{lock};
		$self->{lock} = undef;
	}

	return 1;
}

sub _daemonize {
	my $self = shift;

	my $pid = fork;
	die "cannot fork: $!\n" unless defined $pid;

	if ($pid) {
		waitpid($pid, 0);
		exit 0;
	}

	require POSIX;
	POSIX::setsid();

	my $second = fork;
	POSIX::_exit(0) if !defined $second || $second > 0;

	umask 077;

	my $log_fh;
	if (open($log_fh, '>>', $self->{log})) {
		open(STDOUT, '>&', $log_fh);
		open(STDERR, '>&', $log_fh);
		close $log_fh;
	} else {
		open(STDOUT, '>', File::Spec->devnull);
		open(STDERR, '>&', \*STDOUT);
	}

	open(STDIN, '<', File::Spec->devnull);

	$self->{logfh} = undef;

	return 1;
}

sub _log {
	my ($self, $message) = @_;

	my $path = $self->{log} || ($self->{control} . '.log');
	$path =~ s/[\r\n]+/ /g;
	$message =~ s/[\r\n]+/ /g;

	if (!defined $self->{logfh}) {
		return unless open($self->{logfh}, '>>', $path);
		my $previous = select($self->{logfh});
		$| = 1;
		select($previous);
	}

	my @now = localtime;
	printf { $self->{logfh} } "[%d] %04d-%02d-%02d %02d:%02d:%02d %s\n",
		$$, $now[5] + 1900, $now[4] + 1, $now[3], $now[2], $now[1], $now[0], $message;

	return 1;
}

1;

__END__

=head1 NAME

Class::Shared::Backend - load a class once and serve objects made from it

=head1 SYNOPSIS

    # Normally started for you by Class::Shared::Frontend, or by hand:
    use Class::Shared::Backend;

    Class::Shared::Backend->new(
        class  => 'Class::Simple',
        socket => '/run/user/1000/class-shared/Class-Simple-1a2b3c4d.sock',
    )->run;

    # On another machine:
    Class::Shared::Backend->new(
        class    => 'Class::Simple',
        host     => '0.0.0.0',
        port     => 7000,
        tls_cert => '/etc/class-shared/server.pem',
        tls_key  => '/etc/class-shared/server-key.pem',
        tls_ca   => '/etc/class-shared/clients-ca.pem',
        token    => $secret,
    )->run;

=head1 DESCRIPTION

The backend holds the one copy of the class.  It loads the module once and then
constructs as many objects from it as its clients ask for, keeping each object
until the connection that asked for it goes away.

    one backend  --  one copy of Class::Simple's code
                 `--  object #1 (client A), object #2 (client B), ...

It answers one request at a time in a select loop, because all the objects share
one interpreter.

=head1 OPTIONS

=over 4

=item class

Required.  The class to serve.  The backend loads it, and will not instantiate
or dispatch to anything else, however the client asks.

=item socket

Unix socket path.  Defaults to L<Class::Shared/socket_path>.  Use this or
C<host>/C<port>, not both.

=item host, port

Listen on TCP instead of a unix socket, over TLS.  C<host> may be C<127.0.0.1>
for local use or an address of this machine to accept remote clients.  A TCP
listener needs C<tls_cert>, C<tls_key>, C<tls_ca> and a C<token>; see
L</TLS>.

=item tls_cert, tls_key

The certificate and private key this listener presents to clients.  The
certificate has to name the address clients use, because they check the name as
well as the chain.

=item tls_ca

PEM file of the CA, or CAs, that clients' certificates must chain to.  Client
certificates are mandatory: a client that presents none, or one signed by
another CA, is dropped during the handshake.

=item token

The shared secret for a TCP listener, which refuses to start without one and
refuses to accept a frame it cannot authenticate.  It is kept even though the
connection is already TLS: the token checks each frame, the certificate checks
the connection, and neither replaces the other.  A unix socket takes no token:
its mode 0600 file already decides who may connect, so its frames carry no
digest at all.  See L</SECURITY>.

=item log

Log file.  Defaults to the control path with C<.log> appended.

=item daemonize

Fork into the background, detach from the terminal and send output to the log.
Off by default, so a failure to load the class or bind the socket is reported
by C<die> to whoever started it.

=item max_clients

How many connections to accept before refusing more, including connections
still handshaking.  Default 128.  A unix client over the limit is sent a signed
C<busy> reply; a TCP client has no TLS session yet to sign one for, so it is
closed and its frontend reports a failed connection.

=item max_objects

How many objects to hold before refusing to construct more.  Default 4096.

=item start_timeout

Seconds to wait for another backend that is shutting down to release its lock.
Default 2.

=item handshake_timeout

Seconds a TCP connection may spend on its TLS handshake before it is dropped
and its slot freed.  Default 5.  Nothing else is bounded by it: a client that
has finished its handshake may sit idle for as long as it likes.

=back

=head1 SINGLETON

Two guards keep it to one backend per class:

=over 4

=item *

An exclusive C<flock> on a control file in the socket directory, held for the
life of the process.  A second backend for the same class exits with an
explanation, whatever transport it was asked to use.

=item *

A unix socket in the way is probed: if something answers, the backend is already
running; if not, the socket is a leftover and is removed.  A TCP port that is in
use fails to bind.

=back

=head1 OBJECT LIFETIME

An object belongs to the connection that created it.  When that connection
closes -- because the frontend was destroyed, the client exited, or the client
process died -- the backend destroys the object.  A client cannot call, or even
see, another client's object: ids are checked against the connection that owns
them.

=head1 PROTOCOL

Every request and reply is a hash reference in a length-prefixed L<Storable>
frame; see L<Class::Shared::Protocol>.  Clients must start with C<hello>.

=over 4

=item hello

C<{ op =E<gt> 'hello', proto =E<gt> 2, class =E<gt> 'Class::Simple' }>.  The
class name must match.  The reply carries the backend's pid and version.

=item new

C<{ op =E<gt> 'new', args =E<gt> [...] }>.  Constructs a new object with those
arguments and replies with its C<id>.  A constructor that dies is reported and
no object is created.

=item call

C<{ op =E<gt> 'call', id =E<gt> $id, method =E<gt> 'name', args =E<gt> [...],
want =E<gt> 'list' | 'scalar' | 'void' }>.  Replies with C<result =E<gt> [ ...
]>, or C<ok =E<gt> 0> with the text of the exception.  C<new>, C<DESTROY> and
C<AUTOLOAD> may not be called, and the id must belong to this connection.

=item ping

C<{ op =E<gt> 'ping' }>.  Counters and identity, for C<class-shared status>.

=item shutdown

C<{ op =E<gt> 'shutdown' }>.  Replies first, then destroys every object and
exits.

=back

=head1 SECURITY

A unix socket is created mode 0600 in a directory only the owner can write to.
That is the whole of its authentication, so it takes neither a token nor TLS,
and its frames carry no digest.

A TCP listener is a TLS endpoint with client certificates: it needs
C<tls_cert>/C<tls_key> to prove which backend it is, and C<tls_ca> to decide
which clients are welcome.  Verification of the client is mandatory
(C<SSL_VERIFY_FAIL_IF_NO_PEER_CERT>), so a client that presents no certificate,
or one signed by another CA, is dropped inside C<accept> and never becomes a
connection with a buffer or an object.  The rejection is logged; there is
nobody to send an explanation to, because they have not been authenticated.

It also needs a C<token>.  With one, every frame carries an HMAC-SHA-256 of its
body, keyed with the token, and the digest is verified before L<Storable::thaw>
is given any of the frame.  That order is what makes the token a guard rather
than a comment: C<thaw> runs code of the sender's choosing, so a peer without
the secret is stopped before deserialisation, not after it.  A wrong or missing
digest ends that connection.  The refusal is signed like any other frame, so a
peer that does not hold the secret cannot read it either.

So the two checks answer different questions.  TLS says which machine is
calling and keeps what it sends private; the token says whether the frame in
front of us was built by somebody who knows the secret.  A stolen certificate is
not a stolen secret, and a leaked secret does not let anybody read the traffic.

A unix socket needs no token, and takes none: it is created mode 0600 in a
directory only the owner can write to, so the kernel has already decided who
may connect and its frames carry no digest.

=head1 TLS

TCP is TLS; there is no unencrypted TCP mode.  C<new> refuses a C<host>/C<port>
listener without C<tls_cert>, C<tls_key> and C<tls_ca>, the same way it refuses
one without a token, so a port cannot be opened in the clear by forgetting an
argument.

The certificate has to name the address clients connect to: a frontend given a
C<tls_ca> checks the name as well as the chain, so an address- or hostname-based
certificate for C<classhost.example.com> is the one to issue for a backend
reached at that name.  A frontend given a C<tls_fingerprint> instead pins this
exact certificate by digest, in which case the name and the signer (a private
CA, or none at all) do not have to satisfy anybody.

The commands that produce the four files, with the C<subjectAltName> the
certificate needs and a working frontend to match, are in
L<Class::Shared/TRANSPORT SECURITY>; F<t/certs/make-certs.sh> in the
distribution generates the same set, with a second CA and impostor
certificates, for the tests.

The handshake is not done in C<accept>.  An accepted socket starts its TLS
layer without a handshake and then finishes it, a little at a time, from the
select loop as that socket becomes readable or writable.  A peer that connects
and then says nothing therefore costs one pending handshake for at most
C<handshake_timeout> seconds (five by default), after which it is dropped and
its slot freed, while every client already connected keeps being served in the
meantime.  Doing the handshake in C<accept> would let
anyone who can reach the port freeze the backend for the length of the timeout,
and the loop is single-threaded, so that would be every client.

=head1 AUTHOR

Nigel Horne

=head1 LICENSE

This module is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
