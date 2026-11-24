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
	} else {
		$socket = Class::Shared::socket_path($target, $opt{dir})
			unless defined $socket;
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
		dir_hint      => $opt{dir},
		control       => $control,
		log           => $opt{log} || ($control . '.log'),
		daemonize     => $opt{daemonize} ? 1 : 0,
		max_clients   => $opt{max_clients} || $DEFAULT_MAX_CLIENTS,
		max_objects   => $opt{max_objects} || $DEFAULT_MAX_OBJECTS,
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
		. ($self->{token} ? ', token required' : '') . ')');

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

	my $listener = IO::Socket::INET->new(
		LocalAddr => $self->{host},
		LocalPort => $self->{port},
		Proto     => 'tcp',
		Listen    => 64,
		ReuseAddr => 1,
	) or die "cannot listen on $self->{host}:$self->{port}: $!\n";

	$self->{listener} = $listener;
	$self->{address} = $self->{host} . ':' . $self->{port};

	$self->_log('this listener is not encrypted; keep it on a trusted network or a tunnel')
		unless $self->{token};

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
		vec($rin, fileno($self->{listener}), 1) = 1;

		for my $client (values %{$self->{clients}}) {
			my $fd = fileno($client->{fh});
			vec($rin, $fd, 1) = 1 if defined $fd;
		}

		my $ready = select(my $rout = $rin, undef, undef, undef);
		next if !defined $ready || $ready <= 0;

		if (vec($rout, fileno($self->{listener}), 1)) {
			$self->_accept;
		}

		for my $key (keys %{$self->{clients}}) {
			my $client = $self->{clients}{$key};
			next unless $client;

			my $fd = fileno($client->{fh});
			next unless defined $fd;
			next unless vec($rout, $fd, 1);

			$self->_serve_client($client);
			last if $self->{stop};
		}
	}

	return 1;
}

sub _accept {
	my $self = shift;

	my $fh = $self->{listener}->accept;
	return unless $fh;

	if (keys %{$self->{clients}} >= $self->{max_clients}) {
		# Signed like every other frame, because the client will check the
		# digest before it thaws the reply.
		my ($bytes) = Class::Shared::Protocol::encode_frame({
			ok    => 0,
			kind  => 'busy',
			error => "backend is serving too many clients ($self->{max_clients})",
		}, $self->{token});
		Class::Shared::Protocol::write_all($fh, $bytes) if defined $bytes;
		close $fh;
		return;
	}

	fcntl($fh, F_SETFD, FD_CLOEXEC);

	$self->{clients}{ fileno($fh) } = {
		fh      => $fh,
		buffer  => '',
		greeted => 0,
		serial  => $self->{next_serial}++,
		objects => {},
	};

	return 1;
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

	if (defined $self->{token}) {
		my $given = defined $message->{token} ? $message->{token} : '';
		if ($given ne $self->{token}) {
			return { ok => 0, kind => 'auth', error => 'bad or missing token' };
		}
	}

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
        class => 'Class::Simple',
        host  => '0.0.0.0',
        port  => 7000,
        token => $secret,
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

Listen on TCP instead of a unix socket.  C<host> may be C<127.0.0.1> for local
use or an address of this machine to accept remote clients.

=item token

A shared secret.  Every frame in both directions is authenticated with it, and
a frame is thawed only after its digest has been checked.  Strongly advised for
a TCP listener, where without it the listener is open to anybody who can reach
the port; see L</SECURITY>.

=item log

Log file.  Defaults to the control path with C<.log> appended.

=item daemonize

Fork into the background, detach from the terminal and send output to the log.
Off by default, so a failure to load the class or bind the socket is reported
by C<die> to whoever started it.

=item max_clients

How many connections to accept before refusing more.  Default 128.

=item max_objects

How many objects to hold before refusing to construct more.  Default 4096.

=item start_timeout

Seconds to wait for another backend that is shutting down to release its lock.
Default 2.

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

C<{ op =E<gt> 'hello', proto =E<gt> 1, class =E<gt> 'Class::Simple', token
=E<gt> $secret }>.  The token, if the backend has one, and the class name must
match.  The reply carries the backend's pid and version.

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

A unix socket is created mode 0600 in a directory only the user can write to.

A TCP listener is plain, unencrypted, and unauthenticated unless C<token> is
set; even with a token the traffic is readable by anyone who can watch it.  Put
it on a private network, or a tunnel, if that matters.

With a token, every frame carries an HMAC-SHA-256 of its body, keyed with the
token, and the digest is verified before L<Storable::thaw> is given any of the
frame.  That order is what makes the token a guard rather than a comment:
C<thaw> runs code of the sender's choosing, so a peer without the secret is
stopped before deserialisation, not after it.  A wrong or missing digest ends
that connection; the peer learns only that the frame failed authentication.  A
listener started without a token thaws whatever arrives, so do not expose one.

=head1 AUTHOR

Nigel Horne

=head1 LICENSE

This module is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
