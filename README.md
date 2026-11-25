## Name

Class::Shared - keep one instance of a class and let other processes call it

## Synopsis

```perl
use Class::Shared::Frontend;

my $simple = Class::Shared::Frontend->new('Class::Simple',
    ctor => [ verbose => 1 ],
);

$simple->do_something($argument);      # runs in the shared backend
```

## Description

Perl has no equivalent of a shared library for classes: every process loads
its own copy of `Class/Simple.pm`, runs its own constructors and keeps its
own state.  For a large class used by many short lived processes that is a lot
of memory and a lot of start up time.

Class::Shared moves the code into one process and lets the others keep a small
proxy: a [Class::Shared::Frontend](https://metacpan.org/pod/Class%3A%3AShared%3A%3AFrontend) standing in for one object, held by a
[Class::Shared::Backend](https://metacpan.org/pod/Class%3A%3AShared%3A%3ABackend) that loaded the class once and does the work.

```
client process            singleton backend process
--------------            -------------------------
Frontend (object #1)  --socket-->  Class::Shared::Backend
Frontend (object #2)  --socket-->  |-- Class::Simple (code, loaded once)
Frontend (object #3)  --socket-->  |-- object #1
                                   |-- object #2
                                   `-- object #3
```

So there is one copy of the class in the system and as many objects as there are
frontends: `Class::Shared::Frontend->new('Class::Simple', ...)` is one call
to `Class::Simple->new(...)`, in the backend.

The frontend never loads the target class, so it stays cheap.  An object lives
as long as the connection that made it; when the frontend goes, the backend
destroys the object, so its `DESTROY` runs once, in the backend.

One backend serves one class, and it is started with the class name baked in,
so a client cannot make it instantiate anything else.  It may be on this machine
(a unix socket, see `Class::Shared::default_dir`) or on another one (TCP).

## Functions

None are exported.  They are used by the frontend and backend, and may be
useful when writing your own client.

- Class::Shared::validate\_class($class)

    Dies unless `$class` looks like a package name.  Guards `require` and the
    socket path against odd input.

- Class::Shared::default\_dir(%options)

    Returns the directory holding this user's sockets: `dir => ...` if given,
    then `$ENV{CLASS_SHARED_DIR}`, then `$ENV{XDG_RUNTIME_DIR}/class-shared`,
    then `/run/user/$uid/class-shared`, then a per-user directory under the
    system temporary directory.

- Class::Shared::ensure\_dir($dir)

    Creates `$dir` with mode 0700 if it does not exist, and returns `(1, undef)`
    or `(0, $why_not)`.  A directory owned by another user, or one that group or
    others can write to, is refused: anybody who can create files there could
    impersonate the backend.

- Class::Shared::socket\_path($class, $dir)

    Returns the socket path for `$class`, mangling the name and appending an
    FNV-1a hash so that two classes cannot share a path by accident.  Dies if the
    result would be too long for a `sockaddr_un`.

- Class::Shared::normalise\_fingerprint($value)

    Turns a certificate fingerprint into the form the TLS layer wants: `sha256$`
    followed by 64 lower case hexadecimal digits.  Accepts what `openssl x509
    \-fingerprint -sha256` prints, with colons and with or without the `sha256$`
    prefix, and dies on anything that is not a SHA-256 digest of the right length.

- Class::Shared::dir\_of($path)

    The directory part of `$path`.

## Transport Security

Authentication belongs to the transport, and the two transports are
deliberately different.

A unix socket is created mode 0600 in a directory only its owner can write to,
so the kernel has already decided who may connect: there is no token and no TLS,
and no frame carries a digest.  The backend, the frontend and [class-shared](https://metacpan.org/pod/class-shared)
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
verified before [Storable::thaw](https://metacpan.org/pod/Storable%3A%3Athaw) sees the body.  So a client that has a
certificate but not the shared secret still cannot make the backend
deserialise, and so run, bytes of its choosing.  The digest authenticates one
frame; TLS authenticates the connection and encrypts it.  Both, because either
one alone has been enough to lose a system.

See ["SECURITY" in Class::Shared::Backend](https://metacpan.org/pod/Class%3A%3AShared%3A%3ABackend#SECURITY) for the backend's side of it and
[Class::Shared::Protocol](https://metacpan.org/pod/Class%3A%3AShared%3A%3AProtocol) for the framing.

## Limitations

- A unix socket is not encrypted: file permissions decide who may connect, and
anything that can read the socket can read the traffic on it.  TCP is always
TLS, and has no unencrypted mode.
- One backend per class, and it answers one call at a time, so a slow method
delays every client of that class.
- Each frontend is one connection: many objects in one process means many file
descriptors in both processes.
- Arguments and return values travel through [Storable](https://metacpan.org/pod/Storable); filehandles, code
references and tied or inside-out objects do not.
- An object cannot outlive its connection, so it cannot be handed to another
process; it lives exactly as long as the frontend that made it.
- The backend is a separate process, so nothing about your process reaches it
unless you send it.  Setting `$ENV{FOO}` in a frontend does not set it in the
backend, and a method that reads `%ENV` (or `chdir`, or a global, or a file
handle) sees the backend's environment, not yours: its `%ENV` is the one the
backend was started with, and every client shares those values.  Pass such
state as arguments if it matters, or set the environment when you start the
backend.

## See Also

[Class::Shared::Frontend](https://metacpan.org/pod/Class%3A%3AShared%3A%3AFrontend), [Class::Shared::Backend](https://metacpan.org/pod/Class%3A%3AShared%3A%3ABackend),
[Class::Shared::Protocol](https://metacpan.org/pod/Class%3A%3AShared%3A%3AProtocol), [class-shared](https://metacpan.org/pod/class-shared).

## Hacking

`README.md` is generated from the POD in this file and must never be edited
by hand.  After changing the POD, run `make readme`, which calls
`maint/regen-readme`; it converts the POD with [Pod::Github](https://metacpan.org/pod/Pod%3A%3AGithub)'s
`pod2github`, the converter whose `##` headings, fenced Perl blocks and
MetaCPAN links are the style the committed front page uses.  `pod2markdown`
does not reproduce it.

[Pod::Github](https://metacpan.org/pod/Pod%3A%3AGithub) is a development requirement, so `cpanm --installdeps
\--with-develop .` installs everything needed to regenerate the front page.

## Author

Nigel Horne

## License

This module is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.
