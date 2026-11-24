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

- Class::Shared::dir\_of($path)

    The directory part of `$path`.

## Limitations

- A unix socket or plain TCP; there is nothing encrypted here.
- One backend per class, and it answers one call at a time, so a slow method
delays every client of that class.
- Each frontend is one connection: many objects in one process means many file
descriptors in both processes.
- Arguments and return values travel through [Storable](https://metacpan.org/pod/Storable); filehandles, code
references and tied or inside-out objects do not.
- The backend answers one call at a time.  A slow method delays every client.
- An object cannot outlive its connection, so it cannot be handed to another
process; it lives exactly as long as the frontend that made it.

## See Also

[Class::Shared::Frontend](https://metacpan.org/pod/Class%3A%3AShared%3A%3AFrontend), [Class::Shared::Backend](https://metacpan.org/pod/Class%3A%3AShared%3A%3ABackend),
[Class::Shared::Protocol](https://metacpan.org/pod/Class%3A%3AShared%3A%3AProtocol), [class-shared](https://metacpan.org/pod/class-shared).

## Author

Nigel Horne

## License

This module is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.
