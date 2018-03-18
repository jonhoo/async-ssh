//! High-level library for asynchronous SSH connections.
//!
//! This crate presents a higher-level asynchronous interface for issuing commands over SSH
//! connections. It's built on top of [thrussh](https://pijul.org/thrussh/), a pure-Rust
//! implementation of the SSH protocol.
//!
//! At its core, the crate provides the notion of an SSH [`Session`], which can have zero or more
//! [`Channel`]s. Each [`Channel`] executes some user-defined command on the remote machine, and
//! implements [`AsyncRead`](https://docs.rs/tokio-io/0.1/tokio_io/trait.AsyncRead.html) and
//! (eventually) [`AsyncWrite`](https://docs.rs/tokio-io/0.1/tokio_io/trait.AsyncWrite.html) to
//! allow reading from and writing to the remote process respectively. For those unfamiliar with
//! asynchronous I/O, you'll likely want to start with the [functions in
//! `tokio-io::io`](https://docs.rs/tokio-io/0.1/tokio_io/io/index.html#functions).
//!
//! The code is currently in a pre-alpha stage, with only a subset of the core features
//! implemented, and with fairly gaping API holes like `thrussh` types being exposed all over
//! the place or error types not being nice to work with.
//!
//! # Examples
//!
//! ```no_run
//! # extern crate tokio_core;
//! # extern crate async_ssh;
//! # extern crate thrussh_keys;
//! # extern crate thrussh;
//! # extern crate tokio_io;
//! # extern crate futures;
//! # use async_ssh::*;
//! # use futures::Future;
//! # fn main() {
//! let key = thrussh_keys::load_secret_key("/path/to/key", None).unwrap();
//!
//! let mut core = tokio_core::reactor::Core::new().unwrap();
//! let handle = core.handle();
//! let ls_out = tokio_core::net::TcpStream::connect(&"127.0.0.1:22".parse().unwrap(), &handle)
//!     .map_err(thrussh::Error::IO)
//!     .map_err(thrussh::HandlerError::Error)
//!     .and_then(|c| Session::new(c, &handle))
//!     .and_then(|session| session.authenticate_key("username", key))
//!     .and_then(|mut session| session.open_exec("ls -la"));
//!
//! let channel = core.run(ls_out).unwrap();
//! let (channel, data) = core.run(tokio_io::io::read_to_end(channel, Vec::new())).unwrap();
//! let status = core.run(channel.exit_status()).unwrap();
//!
//! println!("{}", ::std::str::from_utf8(&data[..]).unwrap());
//! println!("exited with: {}", status);
//! # }
//! ```
#![deny(missing_docs)]

extern crate futures;
extern crate thrussh;
extern crate thrussh_keys;
extern crate tokio_core;
extern crate tokio_io;

use tokio_io::{AsyncRead, AsyncWrite};
use std::rc::Rc;
use std::cell::RefCell;
use futures::Future;

mod session;
mod channel;

pub use channel::{Channel, ChannelOpenFuture, ExitStatusFuture};
pub use session::{NewSession, Session};

struct Connection<S: AsyncRead + AsyncWrite> {
    c: thrussh::client::Connection<S, session::state::Ref>,
    task: Option<futures::task::Task>,
}

struct SharableConnection<S: AsyncRead + AsyncWrite>(Rc<RefCell<Connection<S>>>);
impl<S> Clone for SharableConnection<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn clone(&self) -> Self {
        SharableConnection(self.0.clone())
    }
}

impl<S: AsyncRead + AsyncWrite + thrussh::Tcp> Future for SharableConnection<S> {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> futures::Poll<Self::Item, Self::Error> {
        // NOTE: SessionStateRef as Handler cannot use Rc<RefMut<C<S>>>
        let mut c = self.0.borrow_mut();
        c.task = Some(futures::task::current());
        match c.c.poll() {
            Ok(r) => Ok(r),
            Err(e) => {
                let state = self.0.borrow();
                let state = state.c.handler();
                let mut state = state.borrow_mut();
                state.errored_with = Some(e);
                Err(())
            }
        }
    }
}
