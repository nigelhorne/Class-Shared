package Class::Shared::Frontend;

use strict;
use warnings;

use Fcntl qw(:flock O_RDWR O_CREAT);
use File::Spec ();
use IO::Socket::INET;
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

use Class::Shared ();
use Class::Shared::Protocol ();

our $VERSION = '0.01';

# Seconds to wait for a backend to start up and answer.
our $DEFAULT_TIMEOUT = 10;

our $AUTOLOAD;

my %KNOWN_OPTION = map { $_ => 1 } qw(
	class ctor socket dir host port token token_file autostart timeout log
);

# One frontend stands for one object.  The object itself lives in the backend,
# together with every other object of the same class; the class is loaded there
# once, however many objects and processes there are.
sub new {
	my $class = shift;

	my $target;
	if (@_ && !ref $_[0] && !exists $KNOWN_OPTION{$_[0]}) {
		$target = shift @_;
	}

	my %opt;
	if (@_ == 1 && ref($_[0]) eq 'HASH') {
		%opt = %{ $_[0] };
	} elsif (@_) {
		die "Class::Shared::Frontend->new: expected key/value options\n" if @_ % 2;
		%opt = @_;
	}

	$target = delete $opt{class} if defined $opt{class};

	for my $key (sort keys %opt) {
		die "Class::Shared::Frontend->new: unknown option '$key'\n"
			unless exists $KNOWN_OPTION{$key};
	}

	die "Class::Shared::Frontend->new: no class name given\n"
		unless defined $target && length $target;

	Class::Shared::validate_class($target);

	if (defined $opt{ctor} && ref($opt{ctor}) ne 'ARRAY') {
		die "Class::Shared::Frontend->new: ctor must be an array ref\n";
	}

	my $token = $opt{token};
	$token = Class::Shared::read_secret($opt{token_file}) if defined $opt{token_file};

	my $transport = (defined $opt{host} || defined $opt{port}) ? 'tcp' : 'unix';

	if ($transport eq 'tcp') {
		die "Class::Shared::Frontend->new: a TCP backend needs both host and port\n"
			unless defined $opt{host} && defined $opt{port};
		die "Class::Shared::Frontend->new: use either socket or host/port, not both\n"
			if defined $opt{socket};
	}

	my $socket_path = $transport eq 'unix'
		? ($opt{socket} || Class::Shared::socket_path($target, $opt{dir}))
		: undef;

	my $self = bless {
		class       => $target,
		transport   => $transport,
		socket_path => $socket_path,
		host        => $opt{host},
		port        => $opt{port},
		token       => $token,
		ctor        => $opt{ctor} || [],
		autostart   => exists $opt{autostart} ? $opt{autostart} : 1,
		timeout     => defined $opt{timeout} ? $opt{timeout} : $DEFAULT_TIMEOUT,
		log         => $opt{log} || (($socket_path || Class::Shared::socket_path($target, $opt{dir})) . '.log'),
		sock        => undef,
		pid         => undef,
		id          => undef,
		last_error  => undef,
	}, $class;

	$self->_connect;

	return $self;
}

# ---------------------------------------------------------------- accessors

sub shared_class { $_[0]->{class} }

# The unix socket in use, or undef when talking to a TCP backend.
sub shared_socket_path { $_[0]->{socket_path} }

# A socket path or host:port, whichever this frontend talks to.
sub shared_address {
	my $self = shift;
	return $self->{transport} eq 'tcp'
		? $self->{host} . ':' . $self->{port}
		: $self->{socket_path};
}

# Process id of the backend, and the id of this object inside it.
sub shared_pid { $_[0]->{pid} }
sub shared_id  { $_[0]->{id} }

sub shared_connected { defined $_[0]->{sock} ? 1 : 0 }

sub shared_last_error { $_[0]->{last_error} }

# Explicit dispatch, for method names that clash with the accessors above
# (or with new()).
sub shared_call {
	my $self = shift;
	my $method = shift;

	die "Class::Shared::Frontend->shared_call: no method name given\n"
		unless defined $method && length $method;

	my $want = wantarray;
	my $context = $want ? 'list' : defined($want) ? 'scalar' : 'void';

	my $result = $self->_invoke($method, \@_, $context);

	return @{$result}       if $context eq 'list';
	return                 if $context eq 'void';
	return $result->[0];
}

sub shared_status {
	my $self = shift;

	return $self->_request({ op => 'ping' });
}

# Close the connection.  The object goes with it: the backend destroys
# everything a connection created when that connection goes away, which is
# also what happens if this process dies without closing anything.
sub shared_close {
	my $self = shift;

	return 0 unless $self->{sock};

	close $self->{sock};
	$self->{sock} = undef;
	$self->{id} = undef;
	$self->{pid} = undef;

	return 1;
}

sub DESTROY {
	my $self = shift;
	$self->shared_close if $self->{sock};
	return;
}

# Ask the backend to stop.  That destroys every object it holds, including
# other clients' objects, so it is an administrative operation, not something
# a normal client does.
sub shared_shutdown {
	my $self = shift;

	return 0 unless $self->{sock};

	my $response = eval { $self->_request({ op => 'shutdown' }) };
	my $error = $@;

	$self->shared_close;

	if ($self->{transport} eq 'unix') {
		my $deadline = time + 5;
		while (-e $self->{socket_path} && time < $deadline) {
			select(undef, undef, undef, 0.02);
		}
	}

	die $error if $error;

	return $response->{ok} ? 1 : 0;
}

# ------------------------------------------------------------- dispatching

sub AUTOLOAD {
	my $self = shift;

	my $method = $AUTOLOAD;
	$method =~ s/\A.*:://;

	return if $method eq 'DESTROY';

	die "Class::Shared::Frontend: '$method' called on something that is not a Class::Shared::Frontend object\n"
		unless ref $self;

	my $want = wantarray;
	my $context = $want ? 'list' : defined($want) ? 'scalar' : 'void';

	my $result = $self->_invoke($method, \@_, $context);

	return @{$result}       if $context eq 'list';
	return                 if $context eq 'void';
	return $result->[0];
}

# can() and isa() are inherited from UNIVERSAL, which would answer for the
# frontend rather than for the class it stands in for, so both are overridden.
sub can {
	my ($self, $method) = @_;

	return UNIVERSAL::can($self, $method) unless ref $self;
	return undef unless defined $method;

	# The frontend's own methods are answered locally and honestly.
	my $local = UNIVERSAL::can('Class::Shared::Frontend', $method);
	return $local if $local;

	my $response = eval {
		$self->_request({
			op     => 'call',
			method => 'can',
			args   => [$method],
			want   => 'scalar',
		});
	};

	return undef unless $response && $response->{ok};
	return undef unless ref($response->{result}) eq 'ARRAY' && $response->{result}[0];

	# Answer the way can() normally does: with something callable.
	return sub {
		shift if @_ && defined $_[0] && ref($_[0]) && $_[0] == $self;

		my $want = wantarray;
		my $context = $want ? 'list' : defined($want) ? 'scalar' : 'void';

		my $result = $self->_invoke($method, \@_, $context);

		return @{$result} if $context eq 'list';
		return if $context eq 'void';
		return $result->[0];
	};
}

sub isa {
	my ($self, $class) = @_;

	return UNIVERSAL::isa($self, $class) unless ref $self && defined $class;
	return 1 if $class eq 'Class::Shared::Frontend' or $class eq 'UNIVERSAL';

	my $response = eval {
		$self->_request({
			op     => 'call',
			method => 'isa',
			args   => [$class],
			want   => 'scalar',
		});
	};

	return 0 unless $response && $response->{ok};

	return ref($response->{result}) eq 'ARRAY' && $response->{result}[0] ? 1 : 0;
}

sub _invoke {
	my ($self, $method, $args, $context) = @_;

	my $response = $self->_request({
		op     => 'call',
		method => $method,
		args   => $args,
		want   => $context,
	});

	if (!$response->{ok}) {
		my $error = $response->{error};
		$error = "Class::Shared: the backend for '$self->{class}' rejected '$method'"
			unless defined $error && length $error;
		die $error;
	}

	my $result = $response->{result};
	return [] unless ref($result) eq 'ARRAY';

	return $result;
}

# --------------------------------------------------------------- transport

sub _connect {
	my $self = shift;

	my $sock = $self->_greet;

	if (!$sock) {
		my $reason = $self->{last_error} || 'no backend';

		die "Class::Shared: cannot reach a backend for '$self->{class}' at "
			. $self->shared_address . ": $reason\n"
			unless $self->{autostart} && $self->{transport} eq 'unix';

		$sock = $self->_spawn_backend;

		die "Class::Shared: could not start a backend for '$self->{class}': "
			. ($self->{last_error} || 'timed out')
			. ' (socket ' . $self->shared_address . ", log $self->{log})\n"
			unless $sock;
	}

	$self->{sock} = $sock;

	$self->_create_object;

	return $self;
}

sub _open {
	my $self = shift;

	if ($self->{transport} eq 'tcp') {
		my $sock = IO::Socket::INET->new(
			PeerAddr => $self->{host},
			PeerPort => $self->{port},
			Proto    => 'tcp',
			Timeout  => $self->{timeout},
		);

		$self->{last_error} = "cannot connect to " . $self->shared_address . ": $!"
			unless $sock;

		return $sock;
	}

	my $path = $self->{socket_path};

	$self->{last_error} = "no socket at $path";
	return undef unless -S $path;

	my $sock = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $path);
	$self->{last_error} = "cannot connect to $path: $!" unless $sock;

	return $sock;
}

sub _greet {
	my $self = shift;

	my $sock = $self->_open;
	return undef unless $sock;

	my ($response, $error) = $self->_roundtrip($sock, {
		op    => 'hello',
		proto => $Class::Shared::PROTOCOL_VERSION,
		class => $self->{class},
		pid   => $$,
		token => $self->{token},
	});

	if (!defined $response) {
		close $sock;

		# A backend with a token will not let a frame it cannot
		# authenticate through, and its replies are signed too, so a
		# client with no token cannot read them.
		my $why = defined $self->{token}
			? $error
			: "$error (this backend may require a token)";

		$self->{last_error} = "handshake failed: $why";
		return undef;
	}

	if (!$response->{ok}) {
		close $sock;
		die 'Class::Shared: ' . ($response->{error} || 'the backend refused the handshake') . "\n";
	}

	$self->{pid} = $response->{pid};
	$self->{last_error} = undef;

	return $sock;
}

sub _create_object {
	my $self = shift;

	my $response = $self->_request({ op => 'new', args => $self->{ctor} });

	if (!$response->{ok}) {
		my $error = $response->{error} || 'the backend gave no reason';
		$self->shared_close;
		die "Class::Shared: could not construct $self->{class}: $error\n";
	}

	$self->{id} = $response->{id};

	return $self;
}

sub _request {
	my ($self, $message) = @_;

	$message->{id} = $self->{id} if ($message->{op} || '') eq 'call';

	die "Class::Shared: this frontend has no connection to a backend for '$self->{class}'; "
		. "its object is gone\n" unless $self->{sock};

	my ($response, $error) = $self->_roundtrip($self->{sock}, $message);

	if (!defined $response) {
		$self->shared_close;
		$self->{last_error} = $error;
		die "Class::Shared: lost the backend for '$self->{class}': $error\n";
	}

	return $response;
}

sub _roundtrip {
	my ($self, $sock, $message) = @_;

	# With a token every frame is signed, and the backend checks the digest
	# before it thaws: this is what stops the request bytes from being code.
	my ($bytes, $encode_error) = Class::Shared::Protocol::encode_frame($message, $self->{token});
	if (!defined $bytes) {
		return (undef, $encode_error);
	}

	my ($ok, $write_error) = Class::Shared::Protocol::write_all($sock, $bytes);
	return (undef, $write_error) unless $ok;

	my ($response, $read_error)
		= Class::Shared::Protocol::read_frame($sock, undef, $self->{token});
	return (undef, $read_error) unless defined $response;

	if (ref($response) ne 'HASH') {
		return (undef, 'malformed response from the backend');
	}

	return ($response);
}

# ------------------------------------------------------------ spawning

sub _spawn_backend {
	my $self = shift;

	my $path = $self->{socket_path};
	my $dir  = Class::Shared::dir_of($path);

	my ($dir_ok, $dir_error) = Class::Shared::ensure_dir($dir);
	if (!$dir_ok) {
		$self->{last_error} = $dir_error;
		return undef;
	}

	my $lock_path = $path . '.spawn';
	my $lock;
	if (!sysopen($lock, $lock_path, O_RDWR | O_CREAT, 0600)) {
		$self->{last_error} = "cannot open $lock_path: $!";
		return undef;
	}
	if (!flock($lock, LOCK_EX)) {
		$self->{last_error} = "cannot lock $lock_path: $!";
		close $lock;
		return undef;
	}

	# Somebody else may have started it while we waited for the lock.
	if (my $sock = eval { $self->_greet }) {
		close $lock;
		return $sock;
	}

	# We hold the lock, so a socket that will not answer is a leftover.
	unlink $path if -e $path;

	my $pid = fork;
	if (!defined $pid) {
		$self->{last_error} = "fork failed: $!";
		close $lock;
		return undef;
	}

	if ($pid == 0) {
		$self->_exec_backend($lock);
		# not reached
	}

	waitpid($pid, 0);

	my $deadline = time + $self->{timeout};
	my $sock;

	while (time <= $deadline) {
		my $greeted = eval { $self->_greet };
		if (my $handshake_error = $@) {
			$handshake_error =~ s/\s+\z//;
			$self->{last_error} = $handshake_error;
		}
		if ($greeted) {
			$sock = $greeted;
			last;
		}
		select(undef, undef, undef, 0.02);
	}

	close $lock;

	return $sock;
}

# Runs in the freshly forked child; never returns.
sub _exec_backend {
	my ($self, $lock) = @_;

	require POSIX;

	close $lock if $lock;

	POSIX::setsid();

	# Double fork so the daemon is reaped by init, not by the client.
	my $pid = fork;
	POSIX::_exit(0) if !defined $pid || $pid > 0;

	for my $fd (3 .. 1023) {
		POSIX::close($fd);
	}

	open(STDIN, '<', File::Spec->devnull);

	my $log_opened = open(my $log_fh, '>>', $self->{log});
	if ($log_opened) {
		open(STDOUT, '>&', $log_fh);
		open(STDERR, '>&', $log_fh);
		close $log_fh;
	} else {
		open(STDOUT, '>', File::Spec->devnull);
		open(STDERR, '>&', \*STDOUT);
	}

	my @inc = grep { defined($_) && !ref($_) && length($_) } @INC;

	no warnings 'exec';    # exec() does not return when it works
	exec(
		$^X,
		(map { ('-I', $_) } @inc),
		'-MClass::Shared::Backend',
		'-e',
		'Class::Shared::Backend->new(class => $ARGV[0], socket => $ARGV[1], log => $ARGV[2])->run()',
		$self->{class},
		$self->{socket_path},
		$self->{log},
	);

	POSIX::_exit(127);
}

1;

__END__

=head1 NAME

Class::Shared::Frontend - a stand-in for one object that lives in a backend

=head1 SYNOPSIS

    use Class::Shared::Frontend;

    # Stands in for Class::Simple->new(verbose => 1), but the object is
    # constructed in the shared backend and this process runs none of the
    # class's code.
    my $simple = Class::Shared::Frontend->new('Class::Simple',
        ctor => [verbose => 1],
    );

    my $answer = $simple->do_something($arg);

    # A backend on another machine:
    my $remote = Class::Shared::Frontend->new('Class::Simple',
        host       => 'classhost.example.com',
        port       => 7000,
        token_file => '/etc/class-shared/token',
        ctor       => [verbose => 1],
    );

=head1 DESCRIPTION

Each frontend stands for one object.  Constructing it asks a
L<Class::Shared::Backend> to run the target's C<new> with the arguments in
C<ctor>, and the backend returns an id.  Every method call is then forwarded
over the socket, applied to that object, and the result comes back.

The backend holds many such objects, all belonging to the one copy of the class
it loaded.  So a hundred client processes with ten objects each still cost one
copy of F<Class/Simple.pm>, while keeping a hundred processes' worth of
independent objects.

The object lives as long as the connection.  When the frontend is destroyed, or
the process exits or dies, the socket closes and the backend destroys everything
that connection created; the target's C<DESTROY> runs there, once.

A frontend never loads the target class.  If no backend is listening on a unix
socket, one is started automatically (C<autostart =E<gt> 0> forbids that, and a
TCP backend is never started for you).

=head1 OPTIONS

    my $frontend = Class::Shared::Frontend->new('Class::Simple', %options);

The class name may be the first argument or C<class =E<gt> 'Class::Simple'>.

=over 4

=item ctor

Array reference of arguments for the target's C<new>.  Defaults to none.

=item dir

Directory for the unix socket.  Defaults to L<Class::Shared/default_dir>.

=item socket

An explicit unix socket path, overriding C<dir> and the derived name.

=item host, port

Talk to a TCP backend on another machine.  Both are required together, and
neither may be combined with C<socket>.  Autostarting does not apply.

=item token, token_file

A shared secret.  Every frame in both directions is authenticated with it, and
the backend checks the digest before it deserialises anything; a frontend whose
token is wrong is refused at the handshake and gets no object.  A TCP backend
always has one, since it will not start without a token.  Prefer C<token_file>;
a secret passed as C<token> is visible to anything that can read this process's
memory or command line.

=item autostart

True by default.  When false, a missing unix backend is an error.

=item timeout

Seconds to wait for a backend that is being started, and for a TCP connect.
Default 10.

=item log

Where a backend started by this frontend should write.  Defaults to the socket
path with C<.log> appended.

=back

=head1 METHODS

The object answers any method the target class has:

    $frontend->any_method(@args);

Calling context is preserved: in list context the backend calls the method in
list context and every value comes back; in scalar context the scalar result
comes back; in void context nothing is returned.  Exceptions thrown by the
target are rethrown in the caller with their original message, so C<eval> and
C<$@> work as they did before the object moved.

C<can> and C<isa> are answered by the backend; C<can> returns something callable,
as Perl callers expect.

There are also methods for the connection itself:

=over 4

=item shared_class

The class being wrapped.

=item shared_address

The socket path, or C<host:port> for a TCP backend.

=item shared_socket_path

The unix socket path, or undef for a TCP backend.

=item shared_pid

The backend's process id.

=item shared_id

This object's id inside the backend.

=item shared_connected

True while the connection is open.

=item shared_last_error

Why the last connection attempt failed.

=item shared_call($method, @args)

Dispatch a method explicitly, for names that clash with these methods or with
C<new>.

=item shared_status

Hash reference of the backend's C<ping> reply: C<class>, C<pid>, C<objects>,
C<clients>, C<calls>, C<uptime>, C<started>, C<proto>, C<version>, C<address>.

=item shared_close

Close the connection and give up the object.  The target's C<DESTROY> then runs
in the backend.  Any later call dies.

=item shared_shutdown

Stop the whole backend, destroying every object it holds, including other
clients'.  Administrative, not a normal client operation.

=back

=head1 ERRORS

A call dies if the target dies, if the method does not exist, if the object has
been released, or if the connection is lost.  A lost connection is never
silently replaced by a new object, because that would throw away the state the
caller thought it had.

=head1 SEE ALSO

L<Class::Shared>, L<Class::Shared::Backend>, L<class-shared>.

=head1 AUTHOR

Nigel Horne

=head1 LICENSE

This module is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
