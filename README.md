## Name

Class::Shared - keep one instance of a class and let other processes call it

## Synopsis

```perl
use Class::Shared::Frontend;

my $simple = Class::Shared::Frontend->new('Class::Simple');

$simple->foo('hello');      # runs in the shared backend

print $simple->foo(), "\n"; # Prints "hello"
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

The arguments for that constructor go in `ctor`, as an array reference:
`ctor => [verbose => 1]` is
`Class::Simple->new(verbose => 1)`.  They are used once, when the
frontend connects and asks the backend for the object, and they travel over the
socket, so they must be plain data -- a code reference cannot be sent.  If the
constructor dies, the frontend's `new` dies too, naming the class and the error
the backend reported.

[Class::Shared::Frontend](https://metacpan.org/pod/Class%3A%3AShared%3A%3AFrontend) lists every option this constructor takes.

The frontend never loads the target class, so it stays cheap.  An object lives
as long as the connection that made it; when the frontend goes, the backend
destroys the object, so its `DESTROY` runs once, in the backend.

One backend serves every class its clients ask for.  A client names the class it
wants in its first message, the handshake, and the backend loads that module
then, once per class, however many clients ask for it.  The backend may be on
this machine (a unix socket, see `Class::Shared::default_dir`) or on another
one (TCP).

Class::Shared is for Unix-like systems: unix sockets, POSIX directory
permissions and `fork` are what make a backend reachable, private and
startable.  See ["PLATFORMS"](#platforms).

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

- Class::Shared::socket\_path($dir)

    Returns the path of the backend socket in `$dir`, or in the default directory
    if none is given.  There is one socket for every class, because the class is
    chosen by the client rather than by the listener.  Dies if the result would be
    too long for a `sockaddr_un`.

- Class::Shared::client\_tls\_options(%options)

    The TLS options an [IO::Socket::SSL](https://metacpan.org/pod/IO%3A%3ASocket%3A%3ASSL) client needs, as a list to pass straight
    to `IO::Socket::SSL->new(...)`: `cert` and `key`, plus either `ca` (a
    PEM file, with the certificate's name checked too) or `fingerprint` (a digest
    from `Class::Shared::normalise_fingerprint`, which replaces both the CA and
    the name).
    [Class::Shared::Frontend](https://metacpan.org/pod/Class%3A%3AShared%3A%3AFrontend) and [class-shared](https://metacpan.org/pod/class-shared) both use it, so the two cannot
    disagree about what verifying a backend means.  Loads [IO::Socket::SSL](https://metacpan.org/pod/IO%3A%3ASocket%3A%3ASSL) when
    called, and nothing else does.

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

### Making the Certificates

A TCP listener needs four files: a CA, the listener's certificate and key, and
a certificate for every client.  OpenSSL makes them in three steps.  The CA's
key signs certificates and is not needed on the machines that use them.

```
# 1. A CA of your own.
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout ca-key.pem -out ca.pem -subj '/CN=Class::Shared CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign'
```

The listener's certificate has to name the address clients connect to, in
`subjectAltName`: a `DNS:` entry for a hostname, an `IP:` entry for an
address, or both.

```
# 2. The listener's certificate.  Put your own addresses in server.ext.
printf 'subjectAltName = DNS:classhost.example.com, IP:127.0.0.1\n' > server.ext
printf 'extendedKeyUsage = serverAuth\n' >> server.ext
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=classhost.example.com' \
    -keyout server-key.pem -out server.csr
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 3650 -out server.pem -extfile server.ext
```

Each client needs a certificate of its own.  The backend cannot tell one from
another beyond this, so give each client, or each pair of them, their own.

```
# 3. A client certificate.
printf 'extendedKeyUsage = clientAuth\n' > client.ext
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=class-shared client' \
    -keyout client-key.pem -out client.csr
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 3650 -out client.pem -extfile client.ext
```

The listener is given three of the files:

```
class-shared serve --listen tcp:0.0.0.0:7000 \
    --token-file /etc/class-shared/token \
    --tls-cert server.pem --tls-key server-key.pem --tls-ca ca.pem
```

and every client the other three:

```perl
my $simple = Class::Shared::Frontend->new('Class::Simple',
    host       => 'classhost.example.com',
    port       => 7000,
    tls_ca     => 'ca.pem',
    tls_cert   => 'client.pem',
    tls_key    => 'client-key.pem',
    token_file => '/etc/class-shared/token',
);
```

A frontend that pins the listener's certificate instead of trusting the CA skips
`tls_ca` and passes `tls_fingerprint` the digest that
`openssl x509 -in server.pem -noout -fingerprint -sha256` prints.  That works
with a self-signed certificate too, and then the CA is only needed for the
clients.  `t/certs/make-certs.sh` in the distribution generates this set, plus
a second CA and impostor certificates, for the tests.

## Limitations

- A unix socket is not encrypted: file permissions decide who may connect, and
anything that can read the socket can read the traffic on it.  TCP is always
TLS, and has no unencrypted mode.
- One backend per directory answers one call at a time, so a slow method delays
every client of that backend, whatever class they are using.
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
- A socket path given explicitly (the `socket` option, or `--socket`) is not
checked against the `sockaddr_un` length limit, unlike one built by
`Class::Shared::socket_path`.  An over-long path is silently truncated by the
operating system, so a client and a backend can end up on the wrong socket.
Prefer `dir` and let `Class::Shared::socket_path` build the path.
- A client may name any method of the target object, including a
package-qualified one such as `Other::Package::function`, which Perl resolves
without regard to the object's class.  Only `new`, `DESTROY` and `AUTOLOAD`
are refused.  This is inside the trust model, since a client that has passed
the transport's authentication can already make the backend load any module,
but it means the backend is only as safe as the clients allowed to reach it.

## Platforms

Unix-like systems only.  A backend needs three things this distribution cannot
do without:

- unix domain sockets, which is how a frontend reaches a backend on this machine
and starts one when there is none;
- POSIX directory permissions, which are the whole of a unix socket's
authentication: the socket is mode 0600 inside a directory only its owner can
write to, so the kernel decides who may connect;
- a real `fork`, which is how a frontend starts a backend in the background.

A perl without unix domain sockets can run none of it, so that is the question
the check asks, rather than a list of operating systems: a Cygwin perl has the
sockets and works.  Windows has had the sockets since Windows 10, but an
MSWin32 perl still cannot run a backend: its `stat` reports the same mode bits
for every directory, so none there can be shown to be owner-only and
`Class::Shared::ensure_dir` refuses them all.

The refusal names what is missing: `Class::Shared::ensure_dir` and
`Class::Shared::socket_path` die with that explanation on a perl without the
sockets, and `Class::Shared::ensure_dir` refuses the directories it cannot
show to be owner-only.

It installs there anyway, and `Makefile.PL` says so as it runs.  Refusing to
install would take away [Class::Shared::Protocol](https://metacpan.org/pod/Class%3A%3AShared%3A%3AProtocol), which is pure Perl and can
talk to a backend from a machine that cannot run one, and would leave such a
platform with nothing to report but a failed install.

The wire protocol, [Class::Shared::Protocol](https://metacpan.org/pod/Class%3A%3AShared%3A%3AProtocol), is pure Perl and loads on any
platform, so it can be used to talk to a backend from a machine that cannot run
one.

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

Nigel Horne, `<njh at nigelhorne.com>`

## Licence and Copyright

Copyright 2026 Nigel Horne.

Usage is subject to the GPL2 licence terms.
If you use it,
please let me know.
