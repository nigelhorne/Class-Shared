package Class::Shared::Backend;

use strict;
use warnings;

use Carp ();
use Fcntl qw(:flock F_SETFD FD_CLOEXEC O_RDWR O_CREAT);
use File::Spec ();
use IO::Socket::INET;
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);
use Time::HiRes ();

use Class::Shared ();
use Class::Shared::Protocol ();

our $VERSION = '0.001.0';

our $DEFAULT_MAX_CLIENTS = 128;
our $DEFAULT_MAX_OBJECTS = 4096;

# How long a new backend waits, in seconds, for a lock that a backend which is
# shutting down still holds.
our $DEFAULT_START_TIMEOUT = 2;

# The accept queue of the listening socket.
our $LISTEN_BACKLOG = 64;

# The most one read takes from a client.  A larger frame arrives over several
# turns of the loop and waits in that client's buffer.
our $READ_CHUNK = 65536;

# While a TLS handshake is pending the loop wakes this often, in seconds, to
# expire the ones that have run out of time.
our $HANDSHAKE_POLL = 0.25;

# How long a connection may spend on its TLS handshake.  The handshake is done
# a little at a time from the select loop, so a peer that connects and then
# says nothing costs one connection slot for this long, not the whole backend.
our $HANDSHAKE_TIMEOUT = 5;

# How much may be waiting to be written to one client before it is dropped.
# Replies are queued per connection and written from the loop as the socket
# takes them, so this is what stops a client that asks for an answer and then
# stops reading from holding that reply, and the memory for it, indefinitely.
# The default is one maximum-size frame, so no reply the protocol allows is
# refused for being large.
our $MAX_QUEUED = $Class::Shared::Protocol::MAX_FRAME + 4096;

# max_queued bounds how much one client may have waiting; this bounds how long
# it may have it there.  A stalled queue that the socket will not take is a
# client that has stopped reading, and holding its memory for ever is what the
# bound alone allows.  The clock is fractional, so a slow reader that keeps
# taking bytes is not dropped early by the second hand.
our $WRITE_TIMEOUT = 30;

# What a connection is told when it asks for an object before naming a class.
our $NO_CLASS_ERROR = 'this connection named no class in its handshake';

# The backend loads each class a client names, once, and holds many objects
# made from them: one per frontend.  Clients talk to it over a unix socket or
# TCP.
sub new {
	my ($class, %opt) = @_;

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
		$socket = defined $socket
			? Class::Shared::check_socket_path($socket)
			: Class::Shared::socket_path($opt{dir});

		# The socket is mode 0600 in a directory only its owner can write to,
		# so the kernel has already decided who may connect: a digest on every
		# frame would buy nothing here and cost 32 bytes on each message.
		die "Class::Shared::Backend->new: a unix socket needs no token: "
			. "$Class::Shared::UNIX_TRUST_REASON\n"
			if defined $opt{token} && length $opt{token};

		die "Class::Shared::Backend->new: a unix socket needs no TLS: "
			. "$Class::Shared::UNIX_TRUST_REASON\n"
			if grep { defined $opt{$_} && length $opt{$_} } qw(tls_cert tls_key tls_ca);
	}

	my $control = defined $socket
		? $socket
		: Class::Shared::socket_path($opt{dir});

	my $max_queued = defined $opt{max_queued} ? $opt{max_queued} : $MAX_QUEUED;

	# Four times one client's bound by default: enough that a few clients may
	# each be holding a maximum-size reply, small enough that a few hundred
	# cannot each be holding one.
	my $max_queued_total = defined $opt{max_queued_total}
		? $opt{max_queued_total}
		: $max_queued * 4;

	my $self = bless {
		classes       => {},
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
		max_queued    => $max_queued,
		max_queued_total => $max_queued_total,
		write_timeout => defined $opt{write_timeout}
			? $opt{write_timeout}
			: $WRITE_TIMEOUT,
		handshake_timeout => defined $opt{handshake_timeout}
			? $opt{handshake_timeout}
			: $HANDSHAKE_TIMEOUT,
		start_timeout => defined $opt{start_timeout}
			? $opt{start_timeout}
			: $DEFAULT_START_TIMEOUT,
		objects       => {},
		clients       => {},
		queued        => 0,
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
		owns_socket   => 0,
		address       => undef,
	}, $class;

	return $self;
}

sub run {
	my $self = shift;

	$self->_daemonize if $self->{daemonize};

	my $started = eval { $self->_setup; 1 };
	if (!$started) {
		my $error = $@ || 'unknown error';
		$self->_log("fatal: $error");
		die $error unless $self->{daemonize};
		exit 1;
	}

	$self->_log("serving on $self->{address} (pid $$"
		. ($self->{token} ? ', token required' : '')
		. (defined $self->{host} ? ', TLS with client certificates' : '') . ')');

	$self->_loop;
	$self->_cleanup;

	$self->_log('stopped');

	return 0;
}

# Remove the socket only if this object bound it.  A backend that failed to
# start because another one is already serving never owned the path, and
# unlinking it here would leave the live backend running but unreachable.
sub DESTROY {
	my $self = shift;
	return if $self->{cleaned};
	$self->{cleaned} = 1;

	# A destructor must not disturb the $@ or $! of the code that was running
	# when the object went out of scope.
	local ($@, $!);

	if ($self->{owns_socket} && -e $self->{socket}) {
		unlink($self->{socket})
			or Carp::carp("Class::Shared::Backend: cannot remove $self->{socket}: $!");
	}

	return;
}

# The class is the client's choice, so it is loaded when a client asks for it
# rather than at startup: require brings the file in, and import is called
# because a module with exports is normally used with use, not require.  Each
# class is loaded once however many clients want it.
sub _load_class {
	my ($self, $class) = @_;

	return 1 if $self->{classes}{$class};

	my $file = $class;
	$file =~ s{::}{/}g;
	$file .= '.pm';

	eval { require $file; 1 }
		or return (0, "cannot load $class: " . ($@ || 'unknown error'));

	if ($class->can('import')) {
		eval { $class->import; 1 }
			or return (0, "cannot import $class: " . ($@ || 'unknown error'));
	}

	$self->{classes}{$class} = 1;

	return (1);
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
			die "another backend is already serving ($lock_path is locked)\n";
		}
		Class::Shared::poll_pause();
	}
	$self->{lock} = $lock;

	if (defined $self->{socket}) {
		$self->_setup_unix;
	} else {
		$self->_setup_tcp;
	}

	# A listener that leaked into a method's exec'd child would keep the socket
	# open after this backend had gone.
	fcntl($self->{listener}, F_SETFD, FD_CLOEXEC)
		or die "cannot mark the listener close-on-exec: $!\n";

	# The pid file is a convenience for administrators, so failing to write it
	# is logged and not fatal.
	my $pid_path = $self->{control} . '.pid';
	my $pid_fh;
	open($pid_fh, '>', $pid_path)
		&& print({$pid_fh} "$$\n")
		&& close($pid_fh)
		or $self->_log("cannot write $pid_path: $!");

	return 1;
}

sub _setup_unix {
	my $self = shift;

	if (-e $self->{socket}) {
		my $probe = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $self->{socket});
		if ($probe) {
			$self->_close($probe, 'the probe connection');
			die "a backend is already listening on $self->{socket}\n";
		}
		unlink $self->{socket}
			or die "cannot remove the stale socket $self->{socket}: $!\n";
	}

	my $listener = IO::Socket::UNIX->new(
		Type     => SOCK_STREAM,
		Local    => $self->{socket},
		Listen   => $LISTEN_BACKLOG,
		Blocking => 1,
	) or die "cannot listen on $self->{socket}: $!\n";

	chmod 0600, $self->{socket}
		or die "cannot set permissions on $self->{socket}: $!\n";

	$self->{listener} = $listener;
	$self->{address} = $self->{socket};
	$self->{owns_socket} = 1;

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
		Listen    => $LISTEN_BACKLOG,
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
		my $write_deadline;

		vec($rin, fileno($self->{listener}), 1) = 1;

		for my $client (values %{$self->{clients}}) {
			my $fd = fileno($client->{fh});
			next unless defined $fd;

			vec($rin, $fd, 1) = 1;

			if ($client->{handshaking}) {
				$handshaking = 1;

				# A handshake can want to write as well (TLS 1.3 tickets, a
				# full send buffer), so wait for that only when it asked.
				vec($win, $fd, 1) = 1 if $client->{want_write};
			} elsif (length $client->{outbuf}) {
				# A queued reply is waiting for the socket to take it, and has a
				# deadline if it has made no progress yet.
				vec($win, $fd, 1) = 1;

				if (defined $client->{stalled_since}) {
					my $deadline = $client->{stalled_since} + $self->{write_timeout};
					$write_deadline = $deadline
						if !defined $write_deadline || $deadline < $write_deadline;
				}
			}
		}

		# With a handshake in progress, or a queued reply on a deadline, wake up
		# now and then: a peer that never speaks, or one that never reads, would
		# otherwise keep select asleep past the deadline it is on.
		my $timeout = $handshaking ? $HANDSHAKE_POLL : undef;
		if (defined $write_deadline) {
			my $wait = $write_deadline - Time::HiRes::time();
			$wait = 0 if $wait < 0;
			$timeout = $wait if !defined $timeout || $wait < $timeout;
		}

		my $ready = select(my $rout = $rin, my $wout = $win, undef, $timeout);

		$self->_expire_handshakes if $handshaking;
		$self->_expire_writes if defined $write_deadline;

		next if !defined $ready || $ready <= 0;

		if (vec($rout, fileno($self->{listener}), 1)) {
			$self->_accept;
		}

		for my $key (keys %{$self->{clients}}) {
			my $client = $self->{clients}{$key};
			next unless $client;

			my $fd = fileno($client->{fh});
			next unless defined $fd;

			my $readable = vec($rout, $fd, 1);
			my $writable = vec($wout, $fd, 1);

			if ($client->{handshaking}) {
				next unless $readable || ($client->{want_write} && $writable);
				$self->_continue_tls($client);
			} else {
				next unless $readable || $writable;

				$self->_serve_client($client) if $readable;
				$self->_flush($client) if $writable && !$client->{closed};
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

# Drop connections whose queued reply the socket has stopped taking, so a
# client that has stopped reading cannot sit on the memory it was allowed.
sub _expire_writes {
	my $self = shift;

	my $now = Time::HiRes::time();

	for my $client (values %{$self->{clients}}) {
		next if $client->{closed};
		next unless length $client->{outbuf};
		next unless defined $client->{stalled_since};
		next if $client->{stalled_since} + $self->{write_timeout} > $now;

		$self->_drop_client($client, 'a queued reply of ' . length($client->{outbuf})
			. ' bytes made no progress for ' . $self->{write_timeout} . ' second(s)');
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
			my ($bytes) = Class::Shared::Protocol::encode_frame(
				_failure('busy', "backend is serving too many clients ($self->{max_clients})"),
				$self->{token},
			);
			Class::Shared::Protocol::write_all($fh, $bytes) if defined $bytes;
		}

		$self->_close($fh, 'a refused connection');
		return;
	}

	# A unix client that stops reading must not hold the loop either, so every
	# accepted socket is non-blocking from here on, TLS or not.  Neither step
	# can be skipped: a blocking socket stalls everybody, and one that leaks
	# into an exec'd child outlives its connection.
	if (!(fcntl($fh, F_SETFD, FD_CLOEXEC) && defined $fh->blocking(0))) {
		$self->_log("refused a connection: cannot prepare its socket: $!");
		$self->_close($fh, 'a refused connection');
		return;
	}

	my $client = {
		fh      => $fh,
		buffer  => '',
		outbuf  => '',
		greeted => 0,
		serial  => $self->{next_serial}++,
		objects => {},
		closed  => 0,
	};

	if (defined $self->{host}) {
		my $ssl = $self->_start_tls($fh);

		if (!$ssl) {
			$self->_log('refused a TLS connection: '
				. (IO::Socket::SSL::errstr() || 'cannot start a handshake'));
			$self->_close($fh, 'a refused connection');
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

	# _accept has already made it non-blocking; start_SSL keeps that.
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

		# The socket stays non-blocking: a frame, or the TLS record carrying
		# it, that arrives in pieces waits in this client's buffer while the
		# loop serves everybody else.
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

# True when a failed read or write means "not yet", not "gone": a non-blocking
# socket with nothing to give (or no room to take), or a TLS layer waiting for
# the other direction.  The errno it looks at is the one the call that just
# failed produced, never one left over from before it: the caller clears $!.
sub _would_block {
	my ($self, $fh, $direction) = @_;

	$direction = 'read' unless defined $direction;

	return 1 if $!{EAGAIN} || $!{EWOULDBLOCK};

	my $want = "want_$direction";
	return 1 if $fh->can($want) && $fh->$want;

	# A write can be waiting on a TLS layer that has to read something first.
	return 1 if $direction eq 'write' && $fh->can('want_read') && $fh->want_read;

	return 0;
}

sub _serve_client {
	my ($self, $client) = @_;

	# errno outlives a call, and a TLS read can fail for its own reasons
	# without touching it, so clear it and let only this sysread supply the
	# EAGAIN that means "not yet".  Otherwise a genuine TLS error could be
	# mistaken for half a frame and the client would be kept rather than
	# dropped.
	$! = 0;

	my $read = sysread($client->{fh}, my $chunk, $READ_CHUNK);

	if (!defined $read) {
		# Half a frame is not a fault: keep what has arrived and come back
		# when the rest does.  The buffer is per client, so a slow sender
		# only ever delays itself.
		return 1 if $self->_would_block($client->{fh});

		$self->_drop_client($client, 'read error: ' . ($! || 'unknown error'));
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
			$self->_send($client, _failure('protocol', $protocol_error));
			$self->_drop_client($client, $protocol_error);
			last;
		}

		my $response = eval { $self->_dispatch($client, $message) };
		if ($@) {
			my $internal = $@;
			$internal =~ s/\s+\z//;
			$self->_log("internal error while handling a request: $internal");
			$response = _failure('internal', $internal);
		}

		$self->_send($client, $response) if defined $response;

		last if $client->{closed};
		last if $self->{stop};
	}

	return 1;
}

# The connection owns its objects: when it goes, they go, and the target's
# DESTROY runs here rather than being lost with a dead client.
sub _drop_client {
	my ($self, $client, $reason) = @_;

	return 1 if $client->{closed};

	$self->_log('dropped a client: ' . (defined $reason && length $reason ? $reason : 'no reason given'));

	# Whatever was waiting to be written goes with the connection: there is
	# nobody left to read it.
	$self->{queued} -= length $client->{outbuf};
	$self->{queued} = 0 if $self->{queued} < 0;

	$client->{closed} = 1;
	$client->{outbuf} = '';
	$client->{stalled_since} = undef;

	my $owned = $client->{objects} || {};
	for my $id (keys %{$owned}) {
		delete $self->{objects}{$id};
	}
	%{$owned} = ();

	my $fd = fileno($client->{fh});
	$self->_close($client->{fh}, 'a client connection');
	delete $self->{clients}{$fd} if defined $fd;

	return 1;
}

sub _send {
	my ($self, $client, $message) = @_;

	return if $client->{closed};

	my ($bytes, $encode_error) = Class::Shared::Protocol::encode_frame($message, $self->{token});

	if (!defined $bytes) {
		my $error = $encode_error;
		($bytes) = Class::Shared::Protocol::encode_frame(
			_failure('protocol', $error),
			$self->{token},
		);

		# Neither the reply nor the frame saying it could not be sent can be
		# encoded, so this client will never hear anything: say so here.
		if (!defined $bytes) {
			$self->_log("cannot encode a reply: " . ($encode_error || 'unknown error'));
			return;
		}
	}

	# Measure the queues before any of this reply goes out, so the limits are on
	# what the backend is holding and not on how much of it the kernel happened
	# to take.
	my $length = length $bytes;
	my $queued = length($client->{outbuf}) + $length;

	if ($queued > $self->{max_queued}) {
		$self->_drop_client($client, "a reply of $length bytes leaves $queued "
			. "waiting to be written, more than the $self->{max_queued} a client may hold");
		return;
	}

	# One client's bound is not the process's: a few hundred clients that each
	# stay under max_queued would still add up to more memory than there is.
	if ($self->{queued} + $length > $self->{max_queued_total}) {
		$self->_drop_client($client, "a reply of $length bytes would leave "
			. ($self->{queued} + $length) . ' queued across all clients, more than '
			. "the $self->{max_queued_total} the backend may hold");
		return;
	}

	# The stall clock belongs to the queue, and it starts with it: this is the
	# only place a queue begins.  _flush restarts it on every write that takes
	# bytes out and clears it when the queue empties; nothing else sets it, so a
	# waiting reply can only get older, never fresher.  A reply added to a queue
	# that is already waiting does not get a new deadline.
	$client->{stalled_since} = Time::HiRes::time()
		unless length $client->{outbuf};

	$client->{outbuf} .= $bytes;
	$self->{queued} += $length;

	$self->_flush($client);

	return;
}

# Write as much of a client's queue as the socket will take right now.  What is
# left waits for the loop, which asks for writability again rather than
# sitting here until the client reads.
sub _flush {
	my ($self, $client) = @_;

	return if $client->{closed} || !length $client->{outbuf};

	# errno outlives a call, and a TLS write can fail without touching it.
	$! = 0;

	my $written = syswrite($client->{fh}, $client->{outbuf});

	if (!defined $written) {
		if ($self->_would_block($client->{fh}, 'write')) {
			# Nothing went out, so the deadline does not move: a socket that keeps
			# taking nothing stays on the clock of its last progress instead of
			# being handed a fresh one every time the loop tries it again.
			return;
		}

		$self->_drop_client($client, 'write error: ' . ($! || 'unknown error'));
		return;
	}

	# A socket that takes nothing and reports no error would keep the fd in the
	# writable set for ever, spinning the loop on a queue that never shrinks.
	if ($written == 0) {
		$self->_drop_client($client, 'write error: peer closed the connection');
		return;
	}

	substr($client->{outbuf}, 0, $written, '');
	$self->{queued} -= $written;

	# Progress, so the clock starts again -- or stops, if there is nothing left
	# to wait for.  _send started it when it made the queue; _expire_writes only
	# reads it; those two lines and this one are the whole of the rule.
	$client->{stalled_since} = length $client->{outbuf} ? Time::HiRes::time() : undef;

	# Anything still queued puts the fd back in the loop's writable set.
	return;
}

# ------------------------------------------------------------- request ops

# Purpose:       build the reply that says a request failed, so every refusal
#                has the same shape and a client can rely on ok, kind and error.
# Entry:         $kind is the machine-readable category (protocol, busy, die,
#                forbidden, ...); $error is the text for a person.
# Exit status:   a hash reference { ok => 0, kind => $kind, error => $error }.
# Side effects:  none.
sub _failure {
	my ($kind, $error) = @_;

	return { ok => 0, kind => $kind, error => $error };
}

sub _dispatch {
	my ($self, $client, $message) = @_;

	if (ref($message) ne 'HASH') {
		return _failure('protocol', 'request is not a hash reference');
	}

	my $op = defined $message->{op} ? $message->{op} : '';

	if ($op eq 'hello') {
		return $self->_op_hello($client, $message);
	}

	if (!$client->{greeted}) {
		return _failure('protocol', 'handshake required');
	}

	return $self->_op_new($client, $message) if $op eq 'new';
	return $self->_op_call($client, $message) if $op eq 'call';
	return $self->_op_ping                  if $op eq 'ping';
	return $self->_op_shutdown              if $op eq 'shutdown';

	return _failure('protocol', "unknown operation '$op'");
}

sub _op_hello {
	my ($self, $client, $message) = @_;

	my $proto = defined $message->{proto} ? $message->{proto} : 0;

	if ($proto != $Class::Shared::PROTOCOL_VERSION) {
		return _failure('protocol',
			"protocol version mismatch: client speaks $proto, this backend speaks "
			. $Class::Shared::PROTOCOL_VERSION);
	}

	# A client may name the class it wants here, and then this connection is
	# for objects of that class.  A client that names none is welcome too: that
	# is how the admin commands ask a backend how it is without asking for
	# anything to be loaded.
	my $wanted = $message->{class};

	if (defined $wanted && length $wanted) {
		my $valid = eval { Class::Shared::validate_class($wanted); 1 };
		if (!$valid) {
			my $error = $@ || 'bad class name';
			$error =~ s/\s+\z//;
			return _failure('protocol', $error);
		}

		my ($loaded, $load_error) = $self->_load_class($wanted);
		return _failure('unknown_class', $load_error)
			unless $loaded;

		$client->{class} = $wanted;
	}

	$client->{greeted} = 1;

	return {
		ok      => 1,
		class   => $client->{class},
		pid     => $$,
		proto   => $Class::Shared::PROTOCOL_VERSION,
		version => $Class::Shared::VERSION,
	};
}

sub _op_new {
	my ($self, $client, $message) = @_;

	my $class = $client->{class};
	return _failure('protocol', $NO_CLASS_ERROR) unless defined $class;

	my $args = $message->{args};
	$args = [] unless defined $args;

	return _failure('protocol', 'new: args must be an array reference')
		unless ref($args) eq 'ARRAY';

	my $held = keys %{$self->{objects}};
	if ($held >= $self->{max_objects}) {
		return _failure('busy', "this backend already holds $held objects, its limit");
	}

	my $object = eval { $class->new(@{$args}) };
	if ($@) {
		return _failure('die', "$@");
	}

	return _failure('protocol', "$class->new did not return an object") unless ref($object);

	my $id = $self->{next_id}++;

	$self->{objects}{$id} = {
		object => $object,
		owner  => $client->{serial},
	};
	$client->{objects}{$id} = 1;
	$self->{constructed}++;

	return { ok => 1, id => $id, class => $class };
}

sub _op_call {
	my ($self, $client, $message) = @_;

	my $class = $client->{class};
	return _failure('protocol', $NO_CLASS_ERROR) unless defined $class;

	my $id = $message->{id};
	return _failure('protocol', 'call: no object id')
		unless defined $id && $id =~ /\A\d+\z/;

	my $entry = $self->{objects}{$id};
	return _failure('unknown_object',
		"no object #$id here; it may have been released or its client has gone")
		unless $entry;

	return _failure('forbidden', "object #$id belongs to another connection")
		unless $entry->{owner} == $client->{serial};

	my $object = $entry->{object};

	my $method = $message->{method};
	return _failure('protocol', 'call: no method name')
		unless defined $method && length $method;

	my $args = $message->{args};
	$args = [] unless defined $args;
	return _failure('protocol', 'call: args must be an array reference')
		unless ref($args) eq 'ARRAY';

	my $want = $message->{want};
	$want = 'scalar' unless defined $want;
	return _failure('protocol', "call: unknown calling context '$want'")
		unless $want =~ /\A(?:list|scalar|void)\z/;

	if ($method eq 'new' or $method eq 'DESTROY' or $method eq 'AUTOLOAD') {
		return _failure('forbidden', "cannot call $method() through Class::Shared");
	}

	# can() and isa() are answered locally as booleans: the code reference
	# that can() normally returns cannot cross the wire.
	if ($method eq 'can' or $method eq 'isa') {
		my $name = $args->[0];
		my $answer = eval { $object->$method($name) ? 1 : 0 };
		return _failure('die', "$@") if $@;
		return { ok => 1, result => [$answer] };
	}

	if (!$class->can($method) && !$class->can('AUTOLOAD')) {
		return _failure('unknown_method', "$class has no method '$method'");
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
		return _failure('die', "$@");
	}

	$self->{calls}++;

	return { ok => 1, result => [@result] };
}

sub _op_ping {
	my $self = shift;

	return {
		ok          => 1,
		classes     => [sort keys %{$self->{classes}}],
		queued      => $self->{queued},
		max_queued_total => $self->{max_queued_total},
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
		$self->_close($self->{listener}, 'the listener');
		$self->{listener} = undef;
	}

	$self->_unlink($self->{socket}) if $self->{owns_socket};

	for my $client (values %{$self->{clients}}) {
		# A reply that was queued when the backend stopped, such as the one
		# that asked it to stop, gets one last chance to go out.
		$self->_flush($client) unless $client->{closed};
		$self->_close($client->{fh}, 'a client connection') unless $client->{closed};
	}

	# Every object the backend still holds is destroyed here, once, in the
	# process that created them.
	%{$self->{objects}} = ();
	%{$self->{clients}} = ();

	$self->_unlink($self->{control} . '.pid');

	if ($self->{lock}) {
		flock($self->{lock}, LOCK_UN)
			or $self->_log("cannot release the lock: $!");
		$self->_close($self->{lock}, 'the lock file');
		$self->{lock} = undef;
	}

	return 1;
}

sub _daemonize {
	my $self = shift;

	my $pid = fork;
	die "cannot fork: $!\n" unless defined $pid;

	if ($pid) {
		# The intermediate child's status is not ours to report: the real
		# backend reports through the log.  waitpid only stops it being left
		# as a zombie, and fails harmlessly if SIGCHLD is ignored.
		waitpid($pid, 0);
		exit 0;
	}

	require POSIX;
	POSIX::setsid()
		or die "cannot start a new session: $!\n";

	my $second = fork;
	POSIX::_exit(0) if !defined $second || $second > 0;

	umask 077;

	my ($detached, $detach_error) = Class::Shared::detach_standard_streams($self->{log});
	die "$detach_error\n" unless $detached;

	$self->{logfh} = undef;

	return 1;
}

# Purpose:       close a handle and log it if the close fails, so that a failure
#                is seen once, in the log, instead of being lost.
# Entry:         $fh is an open handle; $what names it in the message.
# Exit status:   1 on success, 0 on failure.
# Side effects:  closes $fh; may write to the log.
sub _close {
	my ($self, $fh, $what) = @_;

	return 1 if close($fh);

	$self->_log("cannot close $what: " . ($! || 'unknown error'));

	return 0;
}

# Purpose:       remove a file this backend made.  A file that is already gone
#                is what was wanted, so only a real failure is logged.
# Entry:         $path names the file.
# Exit status:   1 if the file is gone afterwards, 0 if it could not be removed.
# Side effects:  unlinks $path; may write to the log.
sub _unlink {
	my ($self, $path) = @_;

	return 1 if unlink($path) || $!{ENOENT};

	$self->_log("cannot remove $path: $!");

	return 0;
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
	# There is nowhere else to report a failure to log, so say whether it worked.
	return printf({ $self->{logfh} } "[%d] %04d-%02d-%02d %02d:%02d:%02d %s\n",
		$$, $now[5] + 1900, $now[4] + 1, $now[3], $now[2], $now[1], $now[0], $message)
		? 1
		: 0;
}

1;

__END__

=encoding utf8

=head1 NAME

Class::Shared::Backend - load a class once and serve objects made from it

=head1 SYNOPSIS

Each example is a different real-world pattern.  Most people never write this
code: a frontend starts a backend for you, and C<class-shared serve> starts one
from the shell.

    use Class::Shared::Backend;

    # 1. In the foreground, on the default unix socket.  run() does not return
    #    until the backend is told to stop (Ctrl-C, SIGTERM or "class-shared stop").
    Class::Shared::Backend->new()->run;

    # 2. An explicit unix socket path (at most 100 characters).
    Class::Shared::Backend->new(
        socket => '/run/user/1000/class-shared/class-shared.sock',
    )->run;

    # 3. In the background.  The process that calls run() EXITS (status 0) once
    #    the background copy has been started, so run() never returns there.
    Class::Shared::Backend->new(daemonize => 1, log => '/tmp/cs.log')->run;

    # 4. Serve other machines, over TLS with client certificates and a token.
    my $secret = 'the secret its clients were given too';
    Class::Shared::Backend->new(
        host     => '0.0.0.0',
        port     => 7000,
        tls_cert => '/etc/class-shared/server.pem',
        tls_key  => '/etc/class-shared/server-key.pem',
        tls_ca   => '/etc/class-shared/clients-ca.pem',
        token    => $secret,
    )->run;

    # 5. Limit what the backend will hold.
    Class::Shared::Backend->new(
        max_clients => 20,
        max_objects => 200,
    )->run;

=head1 DESCRIPTION

A client names the class it wants in its first message, the handshake, and the
backend loads that module then -- C<require> for the file, C<import> for its
exports -- once per class however many clients ask for it.  Each object lives
until the connection that asked for it goes away.

    one backend  --  Class::Simple (code, loaded when first asked for)
                 |--  Class::Other  (code, loaded when first asked for)
                 `--  object #1 (client A), object #2 (client B), ...

It answers one request at a time in a select loop, because all the objects share
one interpreter.

There is no class option: which classes are loaded is decided by the clients,
not by the command line.

=head1 OPTIONS

=over 4

=item socket

Unix socket path.  Defaults to L<Class::Shared/socket_path>.  Use this or
C<host>/C<port>, not both.  It must be at most 100 characters; a longer path
makes C<new> die, because the operating system would otherwise cut it short
without saying so.

=item dir

The directory for the default socket, when C<socket> is not given.  Defaults to
L<Class::Shared/default_dir>.  The lock file, the pid file and the log are kept
next to the socket.

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

Log file.  Defaults to the control path with C<.log> appended.  Every client
the backend drops is written there with the reason it was dropped.

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

=item max_queued

How many bytes may be waiting to be written to one client before it is dropped.
Default one maximum-size frame (64 MiB) plus a little, so no reply the protocol
allows is refused for being large.  Lower it to cap what a client that asks and
does not read can hold; a reply larger than the setting is then dropped rather
than queued.  The bound is per client, so all of them together may hold
C<max_clients> times this, which is more than any machine has; C<max_queued_total>
is what stops that from being reachable.  A queued reply is also dropped if the
socket takes none of it for C<write_timeout> seconds, so this bounds what one
client may have waiting, not how long it may wait.

=item max_queued_total

How many bytes may be waiting to be written to all clients together before the
reply that would pass it is refused.  Default four times C<max_queued>: enough
that a few clients may each be holding a maximum-size reply, small enough that
a few hundred cannot each be holding one.  A reply that would pass it is not
queued and its client is dropped, with a log line giving the total, and its
objects go with it; the alternative is a backend whose memory depends on how
many clients decide to stop reading at once.

=item write_timeout

Seconds a queued reply may go without the socket taking any of it before the
connection is dropped.  Default 30.  C<max_queued> bounds how much one client
may have waiting; without this, a client that has stopped reading could leave a
reply there for ever within that allowance.  Progress is what counts, so a slow
client that keeps taking bytes is not dropped, however long the whole reply
takes; one that takes nothing at all loses its connection, its queued reply and
its objects.

=item start_timeout

Seconds to wait for another backend that is shutting down to release its lock.
Default 2.

=item handshake_timeout

Seconds a TCP connection may spend on its TLS handshake before it is dropped
and its slot freed.  Default 5.  Nothing else is bounded by it: a client that
has finished its handshake may sit idle for as long as it likes.

=back

=head1 METHODS

The schemas in each B<API SPECIFICATION> follow the conventions of
L<Params::Validate::Strict> (for input) and L<Return::Set> (for output).  They
describe the method for people and for tools.  The code does not call those
modules, and this distribution does not depend on them.

=head2 new

    my $backend = Class::Shared::Backend->new(%options);

Checks the options and returns a backend that is ready to run.  It does not
open a socket, take a lock or start anything: that happens in L</run>.  Every
option is described in L</OPTIONS>.

Choose one transport.  With neither C<host> nor C<port> you get a unix socket
(C<socket>, or the default path).  With C<host> and C<port> you get TCP over
TLS, which also needs C<tls_cert>, C<tls_key>, C<tls_ca> and C<token>.  A unix
socket refuses a token and TLS files, because its permissions already decide
who may connect.

B<Side effects:> none, other than building the object.

B<Dies> if the options are inconsistent: only one of C<host> and C<port>;
C<socket> together with C<host>/C<port>; a TCP listener without a token or
without all three TLS files; a unix socket with a token or TLS files; or an
over-long socket path.  (A perl without unix sockets is reported by C<run>, or
by C<new> when it has to work out the default socket path.)

=head3 API SPECIFICATION

=head4 Input

    {
        socket            => { type => 'string',  optional => 1, min => 1, max => 100 },
        dir               => { type => 'string',  optional => 1, min => 1 },
        host              => { type => 'string',  optional => 1, min => 1 },
        port              => { type => 'integer', optional => 1, min => 1, max => 65535 },
        tls_cert          => { type => 'string',  optional => 1, min => 1 },
        tls_key           => { type => 'string',  optional => 1, min => 1 },
        tls_ca            => { type => 'string',  optional => 1, min => 1 },
        token             => { type => 'string',  optional => 1, matches => qr/\A[\x20-\x7E]+\z/ },
        log               => { type => 'string',  optional => 1, min => 1 },
        daemonize         => { type => 'boolean', optional => 1 },
        max_clients       => { type => 'integer', optional => 1, min => 1 },
        max_objects       => { type => 'integer', optional => 1, min => 1 },
        max_queued        => { type => 'integer', optional => 1, min => 1 },
        max_queued_total  => { type => 'integer', optional => 1, min => 1 },
        write_timeout     => { type => 'number',  optional => 1, min => 0 },
        handshake_timeout => { type => 'number',  optional => 1, min => 0 },
        start_timeout     => { type => 'number',  optional => 1, min => 0 },
    }

=head4 Output

    { type => 'object', isa => 'Class::Shared::Backend' }

=head2 run

    my $status = $backend->run;

Starts serving.  In order, it

=over 4

=item 1.

goes into the background, if C<daemonize> is true (see below);

=item 2.

makes sure the socket directory exists and is safe;

=item 3.

takes the lock that makes the backend a singleton (waiting up to
C<start_timeout> seconds for a backend that is shutting down);

=item 4.

opens the listening socket (removing a leftover one that nobody answers on) and
writes the pid file;

=item 5.

serves clients until it is told to stop; and

=item 6.

closes everything, destroys every object, removes the socket and pid file, and
releases the lock.

=back

It stops when it receives C<SIGTERM> or C<SIGINT>, or when a client sends the
C<shutdown> request (for example C<class-shared stop>).  C<SIGHUP> and
C<SIGPIPE> are ignored.

Returns 0 after a normal stop.

B<Background mode.> When C<daemonize> is true, C<run> forks twice.  The process
that called it B<exits with status 0> as soon as the first fork has finished, so
C<run> does not return there.  Only the background copy goes on.  The calling
process does not wait for the background copy to be ready, so the socket may not
exist yet when it exits.  If starting fails in the background copy, the reason is
written to the log and the copy exits with status 1.

B<Side effects:> creates the socket directory, a lock file (C<.owner>), a pid
file (C<.pid>) and a log file (C<.log>) next to the socket; opens the listening
socket; loads each class a client asks for; writes to the log.  The socket and
the pid file are removed at a normal stop.  The lock file and the log are left
in place.

B<Dies> (when not in the background) with the reason if it cannot start: another
backend is serving, the directory is unsafe, this perl has no unix sockets, the
socket cannot be bound, or TLS cannot be set up.  The same reason is written to
the log first.

=head3 API SPECIFICATION

=head4 Input

    { }

=head4 Output

    { type => 'integer', memberof => [0] }

=head2 DESTROY

Called by Perl when the backend object goes away.  It removes the socket file,
but only if this object created it.  A backend that failed to start because
another one was already serving never owned the socket, so it leaves the other
backend's socket alone.  You do not call it yourself.

=head1 SINGLETON

Two guards keep it to one backend per directory:

=over 4

=item *

An exclusive C<flock> on a control file in the socket directory, held for the
life of the process.  A second backend there exits with an explanation,
whatever transport it was asked to use.

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

C<{ op =E<gt> 'hello', proto =E<gt> 2, class =E<gt> 'Class::Simple' }>.  C<proto>
must be the backend's own protocol version.  C<class> is optional: a client that
names none can still use C<ping> and C<shutdown>, which is how C<class-shared
status> works.  A name is checked (see L</ENCODING>) and the class is loaded, once
for the whole backend.  The reply carries the backend's pid and version.

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

C<{ op =E<gt> 'ping' }>.  Counters and identity, for C<class-shared status>:
objects, calls, clients, classes, uptime, C<queued> (the bytes waiting to be
written to all clients together) and C<max_queued_total>, the ceiling those
bytes are held against, so the one number can be read as a fraction of the
other.

=item shutdown

C<{ op =E<gt> 'shutdown' }>.  Replies first, then destroys every object and
exits.

=back

A reply that says C<ok =E<gt> 0> also has a C<kind>, which tells a program what
went wrong, and an C<error>, which tells a person.  The kinds are:

=over 4

=item protocol

The request was malformed, came out of order, or spoke another protocol version.

=item unknown_class

The class could not be loaded.

=item busy

The backend is full: too many clients or too many objects.

=item die

The target's C<new> or method died; C<error> is its message.

=item unknown_object

No such object (it may have been released).

=item unknown_method

The target class has no such method.

=item forbidden

The object belongs to another connection, or the method may not be called.

=item internal

The backend itself failed while handling the request.

=back

=head1 SECURITY

A unix socket is created mode 0600 in a directory only the owner can write to.
That is the whole of its authentication, so it takes neither a token nor TLS,
and its frames carry no digest.

The class is the client's choice.  The handshake loads whatever module is named,
so anybody who can connect can make the backend C<require> any module it can
find, running that module's load-time code.  That is the same power they would
have running perl themselves as the backend's user, which is what a unix
socket's owner-only permissions and a TCP listener's certificate and token are
there to confine: keep them to people you would let run code here.

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

Frame reads are non-blocking too.  A connection that stops halfway through a
frame, or halfway through the TLS record carrying it, keeps what has arrived in
its own buffer; the loop goes on serving everyone else and resumes that
connection when the rest arrives.

Replies are queued per connection and written as the socket takes them, so a
client that asks for an answer and then stops reading holds its own reply, not
the loop.  What it may hold is bounded by C<max_queued>: once more than that is
waiting to be written to it, the client is dropped, since the alternative is
holding the backend's memory for as long as it chooses to stay connected.  For
the same reason a queued reply that makes no progress for C<write_timeout>
seconds is dropped too: the bound caps how much a client may hold, the timeout
caps how long it may hold it.  C<max_queued_total> caps what all of them
together may hold, so the memory a few hundred clients that all stop reading
can pin is a number, not the product of two other numbers.

The handshake is not done in C<accept>.  An accepted socket starts its TLS
layer without a handshake and then finishes it, a little at a time, from the
select loop as that socket becomes readable or writable.  A peer that connects
and then says nothing therefore costs one pending handshake for at most
C<handshake_timeout> seconds (five by default), after which it is dropped and
its slot freed, while every client already connected keeps being served in the
meantime.  Doing the handshake in C<accept> would let
anyone who can reach the port freeze the backend for the length of the timeout,
and the loop is single-threaded, so that would be every client.

=head1 ENCODING

=over 4

=item Arguments, results and error text: full Unicode.

Everything a client sends or receives is a L<Storable> image, which keeps
strings exactly as they are.  Accented letters, any alphabet and emoji pass
through the backend unchanged.  The backend does not look inside them.

=item Class names: ASCII only.

A class name is checked in the handshake.  Only the letters A to Z, digits and
underscores, with C<::> between words, are accepted.

=item The token: ASCII only.

The digest is worked out by L<Digest::SHA> on bytes.  A character above code
point 255 stops it from working, and a character from 128 to 255 gives a
different answer as a Perl string than as the bytes of a file.  Use ASCII.

=item Paths: ASCII is safest.

C<socket>, C<dir>, C<log> and the C<tls_*> files go to the operating system as
they are.  The 100 character limit on a socket path counts characters.

=item The log: not one encoding.

The log has no encoding layer.  A message with only characters up to code point
255 is written as one byte per character (so C<caf\x{e9}> is the Latin-1 byte,
not UTF-8).  A message with a higher character, such as an emoji, is written as
UTF-8, and Perl prints a C<Wide character> warning.  Most log lines are the
backend's own English text; other text can only come from an error in your own
class (for example C<internal error while handling a request: ...>).  Read the
log as bytes, and expect that a line may be in either form.

=back

=head1 COMMON PITFALLS

=over 4

=item With C<daemonize>, C<run> does not return in your program.

The process that calls it exits with status 0 once the background copy is
started.  Put nothing after the call that you need to run.  Also, the process
exits before the background copy is ready, so the socket may not exist at that
moment.

=item Without C<daemonize>, C<run> does not return until the backend stops.

It runs the server loop for as long as the backend lives.

=item Which classes are loaded is decided by the clients.

There is no C<class> option.  The class must be findable in the C<@INC> that the
backend was started with, so start it with the right C<-I> or C<PERL5LIB>.

=item The backend keeps the environment it was started with.

Its C<%ENV> and its current directory are those of whoever started it.  A client
cannot change them.

=item One request at a time.

A slow method makes every other client wait, whatever class they use.

=item A TCP listener needs four things.

C<tls_cert>, C<tls_key>, C<tls_ca> and a C<token>.  A unix socket accepts none of
them, on purpose.

=item Only one backend per directory.

A second backend in the same directory exits with "another backend is already
serving".  That failure does not touch the first backend's socket.

=item A killed backend leaves files behind.

After C<kill -9> the socket file and the pid file stay.  The next backend starts
normally: it finds that nothing answers on the socket and removes it.  The lock
file (C<.owner>) and the log are never removed.

=item The log is never trimmed.

It only grows.  Rotate it yourself (stop the backend, move the file, start it
again), or give C<log> a path that something else rotates.

=item The limits drop clients, not requests.

A client that goes over C<max_queued>, C<max_queued_total> or C<write_timeout>
loses its connection and, with it, its objects.

=item C<max_clients> counts connections that are still shaking hands.

A client over the limit is told "busy" on a unix socket.  On TCP it is simply
closed, because the TLS handshake has not happened.

=item The class's package variables are shared.

All objects of a class live in one process, so all clients see the same package
variables.  Keep state in the object.

=back

=head1 SEE ALSO

L<Class::Shared>, L<Class::Shared::Frontend>, L<Class::Shared::Protocol>,
L<class-shared>.

=head1 AUTHOR

Nigel Horne

=head1 FORMAL SPECIFICATION

This section describes what the backend does in the Z notation, a way of
writing exactly what a program promises using sets and logic.  You do not need
it to use the module.  Read the plain text above first.

Z uses mathematical symbols, so this is the only part of the file that is not
plain ASCII.  A short key:

    x? input      x! output      x' the value of x after the operation
    =>  implies   /\  and        \/  or        ~  not
    ⊥  undef      ⊕  update a function      ⩤  remove from a function (domain subtraction)
    ↦  maps to    ⇸  partial function       #  size of a set

=head2 State

    ┌─ Backend ───────────────────────────────────────────────
    │ classes     : ℙ CLASSNAME               loaded, each once
    │ clients     : FD ⇸ CLIENT               open connections
    │ objects     : ℕ₁ ⇸ (OBJECT × SERIAL)    object id to its object and owner
    │ queued      : ℕ                         bytes waiting to be written, all clients
    │ stop        : 𝔹
    │ owns_socket : 𝔹
    ├─────────────────────────────────────────────────────────
    │ #clients ≤ max_clients ∧ #objects ≤ max_objects
    │ queued = Σ { #c.outbuf | c ∈ ran clients } ∧ queued ≤ max_queued_total
    │ ∀ c ∈ ran clients • ∀ id ∈ c.objects • id ∈ dom objects ∧ owner(objects id) = c.serial
    │ ∀ id ∈ dom objects • ∃ c ∈ ran clients • owner(objects id) = c.serial
    │                                  an object never outlives its connection
    └─────────────────────────────────────────────────────────

and each CLIENT has C<class> (a class name or ⊥), C<greeted> (𝔹), C<serial>,
C<objects> (the ids it made), C<buffer> and C<outbuf> (bytes), and C<closed>.

=head2 new

    ┌─ New ───────────────────────────────────────────────────
    │ opts? : OPTIONS ; out! : RESULT[Backend]
    ├─────────────────────────────────────────────────────────
    │ host? = ⊥ ∧ port? = ⊥ ∧ no token ∧ no tls_*  ∧ #socket ≤ 100  ⇒ out! = value(b) ∧ b is idle
    │ host? ≠ ⊥ ∧ port? ≠ ⊥ ∧ socket? = ⊥ ∧ token ≠ ⊥ ∧ tls_cert, tls_key, tls_ca ≠ ⊥
    │                                                    ⇒ out! = value(b) ∧ b is idle
    │ any other combination ⇒ ∃ m • out! = dies(m)
    └─────────────────────────────────────────────────────────

=head2 run

    ┌─ Run ───────────────────────────────────────────────────
    │ ΔBackend ; out! : RESULT[{0}]
    ├─────────────────────────────────────────────────────────
    │ setup succeeds ⇒ owns_socket' = (transport = unix)
    │                  ∧ (the loop runs until stop = true)
    │                  ∧ at the end: clients' = ∅ ∧ objects' = ∅ ∧ owns_socket' = false ∧ out! = value(0)
    │ setup fails ∧ ¬ daemonize ⇒ out! = dies(e) ∧ owns_socket' = false
    │ setup fails ∧ daemonize   ⇒ the background process exits 1
    │ daemonize ⇒ the calling process exits 0 and out! is never seen
    └─────────────────────────────────────────────────────────

=head2 hello

    ┌─ Hello ─────────────────────────────────────────────────
    │ ΔBackend ; c : CLIENT ; proto? : ℕ ; class? : STRING⊥ ; out! : REPLY
    ├─────────────────────────────────────────────────────────
    │ proto? ≠ PROTOCOL_VERSION ⇒ out! = failure(protocol) ∧ ΞBackend
    │ class? ∉ CLASSNAME ∧ class? ≠ ⊥ ⇒ out! = failure(protocol)
    │ class? ∈ CLASSNAME ∧ load fails ⇒ out! = failure(unknown_class)
    │ otherwise ⇒ c.greeted' = true ∧ c.class' = class?
    │             ∧ classes' = classes ∪ {class? | class? ≠ ⊥} ∧ out!.ok = true
    └─────────────────────────────────────────────────────────

=head2 new (the request)

    ┌─ NewObject ─────────────────────────────────────────────
    │ ΔBackend ; c : CLIENT ; args? : seq DATA ; out! : REPLY
    ├─────────────────────────────────────────────────────────
    │ ¬ c.greeted ⇒ failure(protocol)            c.class = ⊥ ⇒ failure(protocol)
    │ #objects ≥ max_objects ⇒ failure(busy)
    │ c.class->new(args?) dies ⇒ failure(die)
    │ c.class->new(args?) = o ∧ o is a reference
    │     ⇒ ∃ id ∉ dom objects • objects' = objects ⊕ {id ↦ (o, c.serial)}
    │           ∧ c.objects' = c.objects ∪ {id} ∧ out! = (ok, id)
    └─────────────────────────────────────────────────────────

=head2 call

    ┌─ Call ──────────────────────────────────────────────────
    │ ΔBackend ; c : CLIENT ; id?, m? : ... ; args? : seq DATA ; want? : {list, scalar, void}
    ├─────────────────────────────────────────────────────────
    │ id? ∉ dom objects ⇒ failure(unknown_object)
    │ id? ∈ dom objects ∧ owner(objects id?) ≠ c.serial ⇒ failure(forbidden)
    │ m? ∈ {"new", "DESTROY", "AUTOLOAD"} ⇒ failure(forbidden)
    │ the class has no method m? ⇒ failure(unknown_method)
    │ the method dies with e ⇒ failure(die)               objects' = objects
    │ the method returns r ⇒ out! = (ok, shape(want?, r))   calls' = calls + 1
    └─────────────────────────────────────────────────────────

=head2 ping and shutdown

    ┌─ Ping ──────────────────────────────────────────────────
    │ ΞBackend ; c.greeted = true ; out! = (ok, counters of the state above)
    └─────────────────────────────────────────────────────────

    ┌─ Shutdown ──────────────────────────────────────────────
    │ ΔBackend ; c.greeted = true
    ├─────────────────────────────────────────────────────────
    │ stop' = true ∧ out! = (ok, "shutting down")     the reply is sent first
    └─────────────────────────────────────────────────────────

=head2 drop a client

    ┌─ Drop ──────────────────────────────────────────────────
    │ ΔBackend ; c : CLIENT ; reason? : STRING
    ├─────────────────────────────────────────────────────────
    │ c ∈ ran clients
    │ objects' = c.objects ⩤ objects                      its objects are destroyed
    │ clients' = clients \ {c's descriptor}               the connection is closed
    │ queued' = queued - #c.outbuf                        its queued reply is discarded
    │ a log line records reason?
    └─────────────────────────────────────────────────────────

=head1 STATE DIAGRAM

First, the life of the backend process.  Then, the life of one client
connection inside it.

=head2 The backend

    +------+  run()  +----------+  lock taken, socket bound  +---------+
    | IDLE | ------> | STARTING | -------------------------> | SERVING | <-+
    +------+         +----------+                            +---------+   | requests keep
                          |                                       |      --+ it SERVING
             something    |                       SIGTERM, SIGINT |
             fails        v                       or "shutdown"   v
                     +----------+                            +----------+
                     |  FAILED  |                            | STOPPING |
                     +----------+                            +----------+
                                                                   |
                                                    cleanup done   v
                                                              +---------+
                                                              | STOPPED |
                                                              +---------+

=over 4

=item IDLE to STARTING

Trigger: C<run>.  Action: if C<daemonize>, fork twice (the caller exits 0); then
check the directory, take the lock, and open the socket.

=item STARTING to SERVING

Trigger: the socket is open.  Action: the pid file is written and C<serving on
...> is logged.  A unix backend now owns its socket.

=item STARTING to FAILED

Trigger: another backend holds the lock or the socket, the directory is unsafe,
TLS cannot be set up, or the bind fails.  Action: the reason is logged.  The
foreground C<run> dies; a background copy exits with status 1.  The other
backend's socket is not touched.

=item SERVING to SERVING

Trigger: a client connects, sends a request, or goes away.  Action: see the
client diagram below.

=item SERVING to STOPPING

Trigger: C<SIGTERM>, C<SIGINT> or a C<shutdown> request.  Action: the loop ends.

=item STOPPING to STOPPED

Trigger: cleanup finishes.  Action: queued replies get one last try to be sent,
all connections are closed, every object is destroyed (so each C<DESTROY> runs,
here), the socket and pid file are removed, the lock is released, C<stopped> is
logged and C<run> returns 0.

=back

=head2 One client connection

    +----------+  TCP: start TLS   +-------------+
    | ACCEPTED | ----------------> | HANDSHAKING |
    +----------+                   +-------------+
         |                           |         |
         | unix: no TLS              | done    | fails, or takes longer
         |                           |         | than handshake_timeout
         v                           v         |
    +----------------+ <-------------+         |
    | AWAITING HELLO | <-+  a failed hello      |
    +----------------+ --+  changes nothing     |
         | good hello                           |
         v                                      |
    +---------+  new, call, ping:               |
    | GREETED | <-+  stays GREETED              |
    +---------+ --+  (new adds an object)       |
         |                                      |
         | error, end of file, bad frame,       |
         | or over a limit                      |
         v                                      v
    +----------------------------------------------+
    |  DROPPED: objects destroyed, socket closed,  |
    |  reason logged                               |
    +----------------------------------------------+

=over 4

=item ACCEPTED to HANDSHAKING

Trigger: a TCP client connects (and the backend is not full).  Action: start TLS
without waiting.  The handshake finishes a little at a time from the loop.

=item ACCEPTED to AWAITING HELLO

Trigger: a unix client connects.  Action: none; its socket is already trusted by
its file permissions.

=item ACCEPTED to DROPPED

Trigger: the backend already has C<max_clients> connections.  Action: a unix
client gets a signed C<busy> reply first; a TCP client is just closed.

=item HANDSHAKING to AWAITING HELLO

Trigger: the TLS handshake finishes.  Action: none.

=item HANDSHAKING to DROPPED

Trigger: the handshake fails (for example no client certificate, or one signed
by another CA) or takes longer than C<handshake_timeout>.  Action: logged and
closed; no object was ever made.

=item AWAITING HELLO to GREETED

Trigger: a C<hello> with the right protocol version and a valid, loadable class
(or no class).  Action: the class is loaded once (if new) and the connection is
marked greeted.

=item GREETED to GREETED

Trigger: C<new>, C<call>, C<ping>.  Action: C<new> adds an object owned by this
connection.  C<call> runs a method.  An exception from the target is sent back
as a reply and does not change the state.

=item any state to DROPPED

Trigger: end of file, a read or write error, a frame that is too large or fails
its digest, a reply that would pass C<max_queued> or C<max_queued_total>, a
queued reply that makes no progress for C<write_timeout> seconds.  Action: the connection's objects are destroyed, its queued data is
discarded, the socket is closed, and the reason is logged.  (When the backend
itself stops, it closes every connection during its cleanup; that is not logged
as a drop.)

=back

=head1 LICENSE

This module is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
