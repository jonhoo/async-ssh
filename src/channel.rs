use tokio_io::{AsyncRead, AsyncWrite};
use futures::{self, Async, Future, Poll};
use std::io::prelude::*;
use std::io;
use thrussh;
use session;
use SharableConnection;

pub(crate) struct State {
    pub(crate) closed: bool,

    pub(crate) read_notify: Option<futures::task::Task>,
    pub(crate) data_start: usize,
    pub(crate) data: Vec<u8>,
    pub(crate) eof: bool,

    pub(crate) exit_notify: Option<futures::task::Task>,
    pub(crate) exit_status: Option<u32>,

    pub(crate) open_notify: Option<futures::task::Task>,
    pub(crate) open_state: Option<Result<(), thrussh::ChannelOpenFailure>>,
}

impl Default for State {
    fn default() -> Self {
        State {
            closed: false,

            read_notify: None,
            data_start: 0,
            data: Vec::new(),
            eof: false,

            exit_notify: None,
            exit_status: None,

            open_notify: None,
            open_state: None,
        }
    }
}

/// A newly opened, but not yet established channel.
pub struct ChannelOpenFuture<'a, S: AsyncRead + AsyncWrite> {
    cmd: &'a str,
    session: SharableConnection<S>,
    state: session::state::Ref,
    id: thrussh::ChannelId,
    first_round: bool,
}

impl<'a, S: AsyncRead + AsyncWrite> ChannelOpenFuture<'a, S> {
    pub(crate) fn new(
        cmd: &'a str,
        session: SharableConnection<S>,
        state: session::state::Ref,
        id: thrussh::ChannelId,
    ) -> Self {
        ChannelOpenFuture {
            cmd,
            session,
            state,
            id,
            first_round: true,
        }
    }
}

impl<'a, S: AsyncRead + AsyncWrite + thrussh::Tcp> Future for ChannelOpenFuture<'a, S> {
    type Item = Channel;
    type Error = thrussh::HandlerError<()>;

    fn poll(&mut self) -> futures::Poll<Self::Item, Self::Error> {
        if self.first_round {
            self.session.0.borrow_mut().c.abort_read()?;
            self.first_round = false;
        }

        let mut s = self.state.borrow_mut();
        let state = s.state_for
            .get_mut(&self.id)
            .expect("no state entry for valid channel");

        state.open_notify = None;
        match state.open_state.take() {
            Some(Ok(_)) => {
                {
                    let mut s = self.session.0.borrow_mut();
                    assert!(s.c.channel_is_open(self.id));
                    s.c.exec(self.id, true, self.cmd);
                    // poke connection thread to say that we sent stuff
                    s.task.take().unwrap().notify();
                }

                Ok(Async::Ready(Channel {
                    state: self.state.clone(),
                    id: self.id,
                }))
            }
            Some(Err(e)) => Err(thrussh::HandlerError::Error(thrussh::Error::IO(
                io::Error::new(io::ErrorKind::Other, format!("{:?}", e)),
            ))),
            None => {
                state.open_notify = Some(futures::task::current());
                Ok(Async::NotReady)
            }
        }
    }
}

/// A channel used to communicate with a process running at a remote host.
pub struct Channel {
    state: session::state::Ref,
    id: thrussh::ChannelId,
}

/// A future that will eventually resolve to the exit status of a process running on a remote host.
pub struct ExitStatusFuture {
    state: session::state::Ref,
    id: thrussh::ChannelId,
}

impl Channel {
    /// Get the exit status of the remote process associated with this channel.
    pub fn exit_status(self) -> ExitStatusFuture {
        ExitStatusFuture {
            state: self.state,
            id: self.id,
        }
    }
}

impl Future for ExitStatusFuture {
    type Item = u32;
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut s = self.state.borrow_mut();
        let state = s.state_for
            .get_mut(&self.id)
            .expect("no state entry for valid channel");

        state.exit_notify = None;
        if let Some(e) = state.exit_status {
            Ok(Async::Ready(e))
        } else if state.closed {
            Err(())
        } else {
            state.exit_notify = Some(futures::task::current());
            Ok(Async::NotReady)
        }
    }
}

impl Read for Channel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut s = self.state.borrow_mut();
        let state = s.state_for
            .get_mut(&self.id)
            .expect("no state entry for valid channel");
        let n = ::std::cmp::min(buf.len(), state.data.len() - state.data_start);
        (&mut buf[..n]).copy_from_slice(&state.data[state.data_start..(state.data_start + n)]);

        // NOTE: Vec::drain is an attractive option here (as it would obviate the need for a bunch
        // of the bookkeeping we're doing) but we're choosing not to use it because it copies the
        // entire remaining vector on drop, which could be expensive.
        // See also https://github.com/jonhoo/async-ssh/pull/1.
        state.data_start += n;
        if state.data_start == state.data.len() {
            state.data_start = 0;
            state.data.clear();
        }

        state.read_notify = None;
        if n == 0 && !state.eof {
            state.read_notify = Some(futures::task::current());
            Err(io::Error::new(io::ErrorKind::WouldBlock, ""))
        } else {
            Ok(n)
        }
    }
}
/*
impl Write for Channel {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        //
    }
    fn flush(&mut self) -> Result<()> {}
}
*/

impl AsyncRead for Channel {}
/*
impl AsyncWrite for Channel {
    fn shutdown(&mut self) -> Poll<(), Error> {}
}
*/
