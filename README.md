# async-ssh

[![Crates.io](https://img.shields.io/crates/v/async-ssh.svg)](https://crates.io/crates/async-ssh)
[![Documentation](https://docs.rs/async-ssh/badge.svg)](https://docs.rs/async-ssh/)
[![Build Status](https://travis-ci.org/jonhoo/async-ssh.svg?branch=master)](https://travis-ci.org/jonhoo/async-ssh)

High-level library for asynchronous SSH connections.

This crate presents a higher-level asynchronous interface for issuing commands over SSH
connections. It's built on top of [thrussh](https://pijul.org/thrussh/), a pure-Rust
implementation of the SSH protocol.

At its core, the crate provides the notion of an SSH [`Session`], which can have zero or more
[`Channel`]s. Each [`Channel`] executes some user-defined command on the remote machine, and
implements [`AsyncRead`](https://docs.rs/tokio-io/0.1/tokio_io/trait.AsyncRead.html) and
(eventually) [`AsyncWrite`](https://docs.rs/tokio-io/0.1/tokio_io/trait.AsyncWrite.html) to
allow reading from and writing to the remote process respectively. For those unfamiliar with
asynchronous I/O, you'll likely want to start with the [functions in
`tokio-io::io`](https://docs.rs/tokio-io/0.1/tokio_io/io/index.html#functions).

The code is currently in a pre-alpha stage, with only a subset of the core features
implemented, and with fairly gaping API holes like `thrussh` types being exposed all over
the place or error types not being nice to work with.

## Examples

```rust
let key = thrussh_keys::load_secret_key("/path/to/key", None).unwrap();

let mut core = tokio_core::reactor::Core::new().unwrap();
let handle = core.handle();
let ls_out = tokio_core::net::TcpStream::connect(&"127.0.0.1:22".parse().unwrap(), &handle)
    .map_err(thrussh::Error::IO)
    .map_err(thrussh::HandlerError::Error)
    .and_then(|c| Session::new(c, &handle))
    .and_then(|session| session.authenticate_key("username", key))
    .and_then(|mut session| session.open_exec("ls -la"));

let channel = core.run(ls_out).unwrap();
let (channel, data) = core.run(tokio_io::io::read_to_end(channel, Vec::new())).unwrap();
let status = core.run(channel.exit_status()).unwrap();

println!("{}", ::std::str::from_utf8(&data[..]).unwrap());
println!("exited with: {}", status);
```

# Live-coding

The crate is under development as part of a live-coding stream series intended
for users who are already somewhat familiar with Rust, and who want to see
something larger and more involved be built. For futures-related stuff, I can
also highly recommend @aturon's in-progress [Async in Rust
book](https://aturon.github.io/apr/async-in-rust/chapter.html).

You can find the recordings of past sessions in [this YouTube
playlist](https://www.youtube.com/playlist?list=PLqbS7AVVErFgY2faCIYjJZv_RluGkTlKt).
This crate started out in [this
video](https://www.youtube.com/watch?v=RBQwZthJjoM). To get updates about
future streams, follow me on [Patreon](https://www.patreon.com/jonhoo) or
[Twitter](https://twitter.com/jonhoo).
