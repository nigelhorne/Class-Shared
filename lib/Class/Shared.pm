package Class::Shared;

use strict;
use warnings;

use File::Basename ();
use File::Spec ();

our $VERSION = '0.01';

# Bumped whenever the wire protocol changes in an incompatible way.
our $PROTOCOL_VERSION = 1;

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
sub ensure_dir {
	my ($dir) = @_;

	die "Class::Shared: no directory given\n" unless defined $dir && length $dir;

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

# One socket per class.  The hash keeps names from colliding after the
# mangling, and the backend re-checks the class name during the handshake, so
# a collision can never hand back the wrong class.
sub socket_path {
	my ($class, $dir) = @_;

	validate_class($class);

	$dir = default_dir(dir => $dir);

	my $stem = $class;
	$stem =~ s/[^A-Za-z0-9_.-]+/-/g;
	$stem =~ s/\A-+//;
	$stem =~ s/-+\z//;
	$stem = substr($stem, 0, 48) if length($stem) > 48;

	my $path = File::Spec->catfile($dir, sprintf('%s-%08x.sock', $stem, _fnv32($class)));

	if (length($path) > $MAX_SOCKET_PATH) {
		die sprintf("Class::Shared: socket path '%s' is %d characters, more than the %d allowed; "
			. "set CLASS_SHARED_DIR or pass dir => to a shorter directory\n",
			$path, length($path), $MAX_SOCKET_PATH);
	}

	return $path;
}

# 32 bit FNV-1a, so that both ends can derive the same path without
# depending on a digest module.
sub _fnv32 {
	my ($string) = @_;

	my $hash = 0x811c9dc5;
	for my $byte (unpack('C*', $string)) {
		$hash ^= $byte;
		$hash = ($hash * 0x01000193) & 0xFFFFFFFF;
	}

	return $hash;
}

1;

__END__

=head1 NAME

Class::Shared - keep one instance of a class and let other processes call it

=head1 SYNOPSIS

    use Class::Shared::Frontend;

    my $simple = Class::Shared::Frontend->new('Class::Simple',
        ctor => [ verbose => 1 ],
    );

    $simple->do_something($argument);      # runs in the shared backend

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

The frontend never loads the target class, so it stays cheap.  An object lives
as long as the connection that made it; when the frontend goes, the backend
destroys the object, so its C<DESTROY> runs once, in the backend.

One backend serves one class, and it is started with the class name baked in,
so a client cannot make it instantiate anything else.  It may be on this machine
(a unix socket, see C<Class::Shared::default_dir>) or on another one (TCP).

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

=item Class::Shared::socket_path($class, $dir)

Returns the socket path for C<$class>, mangling the name and appending an
FNV-1a hash so that two classes cannot share a path by accident.  Dies if the
result would be too long for a C<sockaddr_un>.

=item Class::Shared::dir_of($path)

The directory part of C<$path>.

=back

=head1 LIMITATIONS

=over 4

=item *

A unix socket or plain TCP; there is nothing encrypted here.

=item *

One backend per class, and it answers one call at a time, so a slow method
delays every client of that class.

=item *

Each frontend is one connection: many objects in one process means many file
descriptors in both processes.

=item *

Arguments and return values travel through L<Storable>; filehandles, code
references and tied or inside-out objects do not.

=item *

The backend answers one call at a time.  A slow method delays every client.

=item *

An object cannot outlive its connection, so it cannot be handed to another
process; it lives exactly as long as the frontend that made it.

=back

=head1 SEE ALSO

L<Class::Shared::Frontend>, L<Class::Shared::Backend>,
L<Class::Shared::Protocol>, L<class-shared>.

=head1 AUTHOR

Nigel Horne

=head1 LICENSE

This module is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
