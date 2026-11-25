package Class::Shared;

use strict;
use warnings;

use File::Basename ();
use File::Spec ();

our $VERSION = '0.001.0';

# Bumped whenever the wire protocol changes in an incompatible way.  2 added
# the HMAC-SHA-256 digest every frame carries when a token is in use.
our $PROTOCOL_VERSION = 2;

# Longest unix(7) path we are prepared to generate.  The kernel limit is
# 107 characters plus the terminator; leaving headroom keeps us portable.
our $MAX_SOCKET_PATH = 100;

my $CLASS_RE = qr/\A[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*\z/;

sub validate_class {
	my ($class) = @_;

	die "Class::Shared: no class name given\n"
		unless defined $class && length $class;

	die "Class::Shared: '$class' is not a valid class name\n"
		unless $class =~ $CLASS_RE;

	return $class;
}

# A shared secret for a backend listening on a network socket.  Never pass
# secrets on a command line: give a file and let the caller read it.
sub read_secret {
	my ($path) = @_;

	die "Class::Shared: no token file given\n" unless defined $path && length $path;

	open(my $fh, '<', $path) or die "Class::Shared: cannot read $path: $!\n";
	my $secret = do { local $/; <$fh> };
	close $fh;

	$secret = '' unless defined $secret;
	$secret =~ s/\s+\z//;

	die "Class::Shared: $path is empty\n" unless length $secret;

	return $secret;
}

# A SHA-256 fingerprint of a certificate, in the shape IO::Socket::SSL wants
# for SSL_fingerprint.  Accepts the colon-separated form openssl prints, with
# or without a "sha256$" prefix, so a pin can be pasted straight from
# "openssl x509 -fingerprint -sha256".
my $FINGERPRINT_RE = qr{
	\A
	(?: sha256 \$ )?
	( (?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2} | [0-9A-Fa-f]{64} )
	\z
}x;

sub normalise_fingerprint {
	my ($value) = @_;

	die "Class::Shared: no TLS fingerprint given\n"
		unless defined $value && length $value;

	my ($hex) = $value =~ $FINGERPRINT_RE
		or die "Class::Shared: '$value' is not a SHA-256 certificate fingerprint: "
			. "give 64 hexadecimal digits, optionally colon-separated\n";

	$hex =~ s/://g;

	return 'sha256$' . lc $hex;
}

# The TLS options a client hands to IO::Socket::SSL->new, in one place so the
# frontend and the command line cannot drift apart about what verification
# means.  IO::Socket::SSL is loaded here rather than at the top of this module:
# a unix socket never needs any of it.
sub client_tls_options {
	my (%opt) = @_;

	require IO::Socket::SSL;

	my %tls = (
		SSL_cert_file   => $opt{cert},
		SSL_key_file    => $opt{key},
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
	);

	if (defined $opt{fingerprint}) {
		# A pin names one exact certificate, so it stands in for both the CA
		# and the name, and SSL_force_fingerprint makes the digest the only
		# thing that can accept the peer.
		$tls{SSL_fingerprint}       = $opt{fingerprint};
		$tls{SSL_force_fingerprint} = 1;
		$tls{SSL_verifycn_scheme}   = 'none';
	} else {
		$tls{SSL_ca_file} = $opt{ca};
	}

	return %tls;
}

sub dir_of {
	my ($path) = @_;
	my $dir = File::Basename::dirname($path);
	return length $dir ? $dir : '/';
}

# Where per-user sockets live.  Kept short because the path ends up in a
# sockaddr_un, and per-user because the socket is a trust boundary.
sub default_dir {
	my (%opt) = @_;

	return $opt{dir} if defined $opt{dir} && length $opt{dir};

	if (defined $ENV{CLASS_SHARED_DIR} && length $ENV{CLASS_SHARED_DIR}) {
		return $ENV{CLASS_SHARED_DIR};
	}

	if (defined $ENV{XDG_RUNTIME_DIR} && length $ENV{XDG_RUNTIME_DIR} && -d $ENV{XDG_RUNTIME_DIR}) {
		return File::Spec->catdir($ENV{XDG_RUNTIME_DIR}, 'class-shared');
	}

	my $runtime = "/run/user/$>";
	return File::Spec->catdir($runtime, 'class-shared') if -d $runtime;

	return File::Spec->catdir(File::Spec->tmpdir, "class-shared-$>");
}

# Create $dir if needed and make sure nobody else can drop a socket in it.
# Whether this perl can make a unix domain socket, which is what a backend is
# reached through and what a frontend starts one over.  Probed rather than
# assumed from $^O: a Cygwin perl is not MSWin32 and has them, and a platform
# without them is refused whatever it calls itself.  The answer cannot change
# during a run, so it is asked for once.
our $UNIX_SOCKETS;

sub _has_unix_sockets {
	return $UNIX_SOCKETS if defined $UNIX_SOCKETS;

	$UNIX_SOCKETS = eval {
		require Socket;
		require IO::Socket::UNIX;

		socketpair(my $reader, my $writer, Socket::AF_UNIX(), Socket::SOCK_STREAM(), 0)
			? 1
			: 0;
	} ? 1 : 0;

	return $UNIX_SOCKETS;
}

# Nothing here can work without unix domain sockets, so say that where it is
# tried rather than blaming the directory the caller passed: on a platform
# without them there is no directory that would have helped.  Whether they
# exist can be given as an argument, so the refusal is exercised by the suite
# on machines that have them.
sub _require_unix_sockets {
	my ($what, $has_unix_sockets) = @_;

	$has_unix_sockets = _has_unix_sockets() unless defined $has_unix_sockets;

	return if $has_unix_sockets;

	die "Class::Shared: $what is not available here: this perl has no unix "
		. "domain sockets, so a backend could neither be reached nor started.  "
		. "This distribution is Unix-only (see PLATFORMS)\n";
}

sub ensure_dir {
	my ($dir) = @_;

	die "Class::Shared: no directory given\n" unless defined $dir && length $dir;

	_require_unix_sockets('a backend directory');

	if (!-d $dir) {
		mkdir($dir, 0700) or return (0, "cannot create $dir: $!");
	}

	my @stat = stat($dir);
	return (0, "cannot stat $dir: $!") unless @stat;

	return (0, "$dir is owned by uid $stat[4], not by uid $>")
		if $stat[4] != $>;

	return (0, "$dir is writable by group or others; refusing to use it")
		if $stat[2] & 0022;

	return (1);
}

# One socket for every class.  The backend behind it is told which class a
# client wants when that client connects, so the path names no class and one
# backend can serve as many as are asked for.
sub socket_path {
	my ($dir) = @_;

	_require_unix_sockets('a unix socket');

	$dir = default_dir(dir => $dir);

	my $path = File::Spec->catfile($dir, 'class-shared.sock');

	if (length($path) > $MAX_SOCKET_PATH) {
		die sprintf("Class::Shared: socket path '%s' is %d characters, more than the %d allowed; "
			. "set CLASS_SHARED_DIR or pass dir => to a shorter directory\n",
			$path, length($path), $MAX_SOCKET_PATH);
	}

	return $path;
}

1;

__END__

=head1 NAME

Class::Shared - keep one instance of a class and let other processes call it

=head1 SYNOPSIS

    use Class::Shared::Frontend;

    my $simple = Class::Shared::Frontend->new('Class::Simple');

    $simple->foo('hello');      # runs in the shared backend

    print $simple->foo(), "\n";	# Prints "hello"

=head1 DESCRIPTION

Perl has no equivalent of a shared library for classes: every process loads
its own copy of F<Class/Simple.pm>, runs its own constructors and keeps its
own state.  For a large class used by many short lived processes that is a lot
of memory and a lot of start up time.

Class::Shared moves the code into one process and lets the others keep a small
proxy: a L<Class::Shared::Frontend> standing in for one object, held by a
L<Class::Shared::Backend> that loaded the class once and does the work.

    client process            singleton backend process
    --------------            -------------------------
    Frontend (object #1)  --socket-->  Class::Shared::Backend
    Frontend (object #2)  --socket-->  |-- Class::Simple (code, loaded once)
    Frontend (object #3)  --socket-->  |-- object #1
                                       |-- object #2
                                       `-- object #3

So there is one copy of the class in the system and as many objects as there are
frontends: C<< Class::Shared::Frontend->new('Class::Simple', ...) >> is one call
to C<< Class::Simple->new(...) >>, in the backend.

The arguments for that constructor go in C<ctor>, as an array reference:
C<ctor =E<gt> [verbose =E<gt> 1]> is
C<< Class::Simple->new(verbose =E<gt> 1) >>.  They are used once, when the
frontend connects and asks the backend for the object, and they travel over the
socket, so they must be plain data -- a code reference cannot be sent.  If the
constructor dies, the frontend's C<new> dies too, naming the class and the error
the backend reported.

L<Class::Shared::Frontend> lists every option this constructor takes.

The frontend never loads the target class, so it stays cheap.  An object lives
as long as the connection that made it; when the frontend goes, the backend
destroys the object, so its C<DESTROY> runs once, in the backend.

One backend serves every class its clients ask for.  A client names the class it
wants in its first message, the handshake, and the backend loads that module
then, once per class, however many clients ask for it.  The backend may be on
this machine (a unix socket, see C<Class::Shared::default_dir>) or on another
one (TCP).

Class::Shared is for Unix-like systems: unix sockets, POSIX directory
permissions and C<fork> are what make a backend reachable, private and
startable.  See L</PLATFORMS>.

=head1 FUNCTIONS

None are exported.  They are used by the frontend and backend, and may be
useful when writing your own client.

=over 4

=item Class::Shared::validate_class($class)

Dies unless C<$class> looks like a package name.  Guards C<require> and the
socket path against odd input.

=item Class::Shared::default_dir(%options)

Returns the directory holding this user's sockets: C<dir =E<gt> ...> if given,
then C<$ENV{CLASS_SHARED_DIR}>, then C<$ENV{XDG_RUNTIME_DIR}/class-shared>,
then F</run/user/$uid/class-shared>, then a per-user directory under the
system temporary directory.

=item Class::Shared::ensure_dir($dir)

Creates C<$dir> with mode 0700 if it does not exist, and returns C<(1, undef)>
or C<(0, $why_not)>.  A directory owned by another user, or one that group or
others can write to, is refused: anybody who can create files there could
impersonate the backend.

=item Class::Shared::socket_path($dir)

Returns the path of the backend socket in C<$dir>, or in the default directory
if none is given.  There is one socket for every class, because the class is
chosen by the client rather than by the listener.  Dies if the result would be
too long for a C<sockaddr_un>.

=item Class::Shared::client_tls_options(%options)

The TLS options an L<IO::Socket::SSL> client needs, as a list to pass straight
to C<IO::Socket::SSL-E<gt>new(...)>: C<cert> and C<key>, plus either C<ca> (a
PEM file, with the certificate's name checked too) or C<fingerprint> (a digest
from C<Class::Shared::normalise_fingerprint>, which replaces both the CA and
the name).
L<Class::Shared::Frontend> and L<class-shared> both use it, so the two cannot
disagree about what verifying a backend means.  Loads L<IO::Socket::SSL> when
called, and nothing else does.

=item Class::Shared::normalise_fingerprint($value)

Turns a certificate fingerprint into the form the TLS layer wants: C<sha256$>
followed by 64 lower case hexadecimal digits.  Accepts what C<openssl x509
-fingerprint -sha256> prints, with colons and with or without the C<sha256$>
prefix, and dies on anything that is not a SHA-256 digest of the right length.

=item Class::Shared::dir_of($path)

The directory part of C<$path>.

=back

=head1 TRANSPORT SECURITY

Authentication belongs to the transport, and the two transports are
deliberately different.

A unix socket is created mode 0600 in a directory only its owner can write to,
so the kernel has already decided who may connect: there is no token and no TLS,
and no frame carries a digest.  The backend, the frontend and L<class-shared>
refuse both for a unix socket rather than let either look like a defence.

TCP is the opposite case.  A port is reachable by anybody who can route to it,
and treating a frame means running what the sender put in it, so a TCP listener
is a TLS listener: it needs a certificate and its key to prove which backend it
is, and a CA to check client certificates against, and it will not start without
all three.  Clients must present a certificate that CA signed, and must verify
the backend's certificate against the CA that signed it -- name included -- or
against a pinned SHA-256 fingerprint of that one certificate, which stands in
for both the CA and the name.  A client whose certificate the backend cannot
verify is dropped during the handshake and never receives a frame.

TLS answers who is on the other end and makes the bytes unreadable.  The token is
kept on top of it, as a second and independent check: with a token every frame
in both directions carries an HMAC-SHA-256 of its body, and the digest is
verified before L<Storable::thaw> sees the body.  So a client that has a
certificate but not the shared secret still cannot make the backend
deserialise, and so run, bytes of its choosing.  The digest authenticates one
frame; TLS authenticates the connection and encrypts it.  Both, because either
one alone has been enough to lose a system.

See L<Class::Shared::Backend/SECURITY> for the backend's side of it and
L<Class::Shared::Protocol> for the framing.

=head2 Making the certificates

A TCP listener needs four files: a CA, the listener's certificate and key, and
a certificate for every client.  OpenSSL makes them in three steps.  The CA's
key signs certificates and is not needed on the machines that use them.

    # 1. A CA of your own.
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout ca-key.pem -out ca.pem -subj '/CN=Class::Shared CA' \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign'

The listener's certificate has to name the address clients connect to, in
C<subjectAltName>: a C<DNS:> entry for a hostname, an C<IP:> entry for an
address, or both.

    # 2. The listener's certificate.  Put your own addresses in server.ext.
    printf 'subjectAltName = DNS:classhost.example.com, IP:127.0.0.1\n' > server.ext
    printf 'extendedKeyUsage = serverAuth\n' >> server.ext
    openssl req -new -newkey rsa:2048 -nodes -subj '/CN=classhost.example.com' \
        -keyout server-key.pem -out server.csr
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
        -CAcreateserial -days 3650 -out server.pem -extfile server.ext

Each client needs a certificate of its own.  The backend cannot tell one from
another beyond this, so give each client, or each pair of them, their own.

    # 3. A client certificate.
    printf 'extendedKeyUsage = clientAuth\n' > client.ext
    openssl req -new -newkey rsa:2048 -nodes -subj '/CN=class-shared client' \
        -keyout client-key.pem -out client.csr
    openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
        -CAcreateserial -days 3650 -out client.pem -extfile client.ext

The listener is given three of the files:

    class-shared serve --listen tcp:0.0.0.0:7000 \
        --token-file /etc/class-shared/token \
        --tls-cert server.pem --tls-key server-key.pem --tls-ca ca.pem

and every client the other three:

    my $simple = Class::Shared::Frontend->new('Class::Simple',
        host       => 'classhost.example.com',
        port       => 7000,
        tls_ca     => 'ca.pem',
        tls_cert   => 'client.pem',
        tls_key    => 'client-key.pem',
        token_file => '/etc/class-shared/token',
    );

A frontend that pins the listener's certificate instead of trusting the CA skips
C<tls_ca> and passes C<tls_fingerprint> the digest that
C<openssl x509 -in server.pem -noout -fingerprint -sha256> prints.  That works
with a self-signed certificate too, and then the CA is only needed for the
clients.  F<t/certs/make-certs.sh> in the distribution generates this set, plus
a second CA and impostor certificates, for the tests.

=head1 LIMITATIONS

=over 4

=item *

A unix socket is not encrypted: file permissions decide who may connect, and
anything that can read the socket can read the traffic on it.  TCP is always
TLS, and has no unencrypted mode.

=item *

One backend per directory answers one call at a time, so a slow method delays
every client of that backend, whatever class they are using.

=item *

Each frontend is one connection: many objects in one process means many file
descriptors in both processes.

=item *

Arguments and return values travel through L<Storable>; filehandles, code
references and tied or inside-out objects do not.

=item *

An object cannot outlive its connection, so it cannot be handed to another
process; it lives exactly as long as the frontend that made it.

=item *

The backend is a separate process, so nothing about your process reaches it
unless you send it.  Setting C<$ENV{FOO}> in a frontend does not set it in the
backend, and a method that reads C<%ENV> (or C<chdir>, or a global, or a file
handle) sees the backend's environment, not yours: its C<%ENV> is the one the
backend was started with, and every client shares those values.  Pass such
state as arguments if it matters, or set the environment when you start the
backend.

=back

=head1 PLATFORMS

Unix-like systems only.  A backend needs three things this distribution cannot
do without:

=over 4

=item *

unix domain sockets, which is how a frontend reaches a backend on this machine
and starts one when there is none;

=item *

POSIX directory permissions, which are the whole of a unix socket's
authentication: the socket is mode 0600 inside a directory only its owner can
write to, so the kernel decides who may connect;

=item *

a real C<fork>, which is how a frontend starts a backend in the background.

=back

A perl without unix domain sockets can run none of it, so that is the question
the check asks, rather than a list of operating systems: a Cygwin perl has the
sockets and works.  Windows has had the sockets since Windows 10, but an
MSWin32 perl still cannot run a backend: its C<stat> reports the same mode bits
for every directory, so none there can be shown to be owner-only and
C<Class::Shared::ensure_dir> refuses them all.

The refusal names what is missing: C<Class::Shared::ensure_dir> and
C<Class::Shared::socket_path> die with that explanation on a perl without the
sockets, and C<Class::Shared::ensure_dir> refuses the directories it cannot
show to be owner-only.

It installs there anyway, and F<Makefile.PL> says so as it runs.  Refusing to
install would take away L<Class::Shared::Protocol>, which is pure Perl and can
talk to a backend from a machine that cannot run one, and would leave such a
platform with nothing to report but a failed install.

The wire protocol, L<Class::Shared::Protocol>, is pure Perl and loads on any
platform, so it can be used to talk to a backend from a machine that cannot run
one.

=head1 SEE ALSO

L<Class::Shared::Frontend>, L<Class::Shared::Backend>,
L<Class::Shared::Protocol>, L<class-shared>.

=head1 HACKING

F<README.md> is generated from the POD in this file and must never be edited
by hand.  After changing the POD, run C<make readme>, which calls
F<maint/regen-readme>; it converts the POD with L<Pod::Github>'s
C<pod2github>, the converter whose C<##> headings, fenced Perl blocks and
MetaCPAN links are the style the committed front page uses.  C<pod2markdown>
does not reproduce it.

L<Pod::Github> is a development requirement, so C<cpanm --installdeps
--with-develop .> installs everything needed to regenerate the front page.

=head1 AUTHOR

Nigel Horne, C<< <njh at nigelhorne.com> >>

=head1 LICENCE AND COPYRIGHT

Copyright 2026 Nigel Horne.

Usage is subject to the GPL2 licence terms.
If you use it,
please let me know.

=cut

1;
