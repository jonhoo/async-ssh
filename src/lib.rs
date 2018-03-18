extern crate futures;
extern crate thrussh;
extern crate thrussh_keys;
extern crate tokio_core;
extern crate tokio_io;

use tokio_io::{AsyncRead, AsyncWrite};
use std::rc::Rc;
use std::cell::RefCell;
use futures::{Async, Future, Poll};
use std::collections::HashMap;
use tokio_core::reactor::Handle;

#[derive(Default)]
struct SessionState {
    state_for: HashMap<thrussh::ChannelId, ChannelState>,
    errored_with: Option<thrussh::HandlerError<()>>,
}

#[derive(Default, Clone)]
struct SessionStateRef(Rc<RefCell<SessionState>>);

use std::ops::Deref;
impl Deref for SessionStateRef {
    type Target = Rc<RefCell<SessionState>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl thrussh::client::Handler for SessionStateRef {
    type Error = ();
    type FutureBool = futures::Finished<(Self, bool), Self::Error>;
    type FutureUnit = futures::Finished<Self, Self::Error>;
    type FutureSign = futures::Finished<(Self, thrussh::CryptoVec), Self::Error>;
    type SessionUnit = futures::Finished<(Self, thrussh::client::Session), Self::Error>;

    fn check_server_key(self, _: &thrussh_keys::key::PublicKey) -> Self::FutureBool {
        futures::finished((self, true))
    }

    fn channel_open_confirmation(
        self,
        channel: thrussh::ChannelId,
        session: thrussh::client::Session,
    ) -> Self::SessionUnit {
        {
            let mut state = self.0.borrow_mut();
            let state = state
                .state_for
                .get_mut(&channel)
                .expect("got data for unknown channel");

            state.open_state = Some(Ok(()));
            if let Some(task) = state.open_notify.take() {
                task.notify();
            }
        }

        futures::finished((self, session))
    }

    fn channel_open_failure(
        self,
        channel: thrussh::ChannelId,
        reason: thrussh::ChannelOpenFailure,
        _: &str,
        _: &str,
        session: thrussh::client::Session,
    ) -> Self::SessionUnit {
        {
            let mut state = self.0.borrow_mut();
            let state = state
                .state_for
                .get_mut(&channel)
                .expect("got data for unknown channel");

            state.open_state = Some(Err(reason));
            if let Some(task) = state.open_notify.take() {
                task.notify();
            }
        }

        futures::finished((self, session))
    }

    fn data(
        self,
        channel: thrussh::ChannelId,
        ext: Option<u32>,
        data: &[u8],
        session: thrussh::client::Session,
    ) -> Self::SessionUnit {
        if ext.is_none() {
            let mut state = self.0.borrow_mut();
            let state = state
                .state_for
                .get_mut(&channel)
                .expect("got data for unknown channel");

            state.data.extend(data);
            if let Some(task) = state.read_notify.take() {
                task.notify();
            }
        } else {
            // TODO: stderr
        }

        futures::finished((self, session))
    }

    fn channel_close(
        self,
        channel: thrussh::ChannelId,
        session: thrussh::client::Session,
    ) -> Self::SessionUnit {
        {
            let mut state = self.0.borrow_mut();
            let state = state
                .state_for
                .get_mut(&channel)
                .expect("got data for unknown channel");

            state.eof = true;
            state.closed = true;
            if let Some(task) = state.read_notify.take() {
                task.notify();
            }
            if let Some(task) = state.exit_notify.take() {
                task.notify();
            }
        }

        futures::finished((self, session))
    }

    fn channel_eof(
        self,
        channel: thrussh::ChannelId,
        session: thrussh::client::Session,
    ) -> Self::SessionUnit {
        {
            let mut state = self.0.borrow_mut();
            let state = state
                .state_for
                .get_mut(&channel)
                .expect("got data for unknown channel");

            state.eof = true;
            if let Some(task) = state.read_notify.take() {
                task.notify();
            }
        }

        futures::finished((self, session))
    }

    fn exit_status(
        self,
        channel: thrussh::ChannelId,
        exit_status: u32,
        session: thrussh::client::Session,
    ) -> Self::SessionUnit {
        {
            let mut state = self.0.borrow_mut();
            let state = state
                .state_for
                .get_mut(&channel)
                .expect("got data for unknown channel");

            state.exit_status = Some(exit_status);
            if let Some(task) = state.exit_notify.take() {
                task.notify();
            }
        }

        futures::finished((self, session))
    }
}

struct Connection<S: AsyncRead + AsyncWrite> {
    c: thrussh::client::Connection<S, SessionStateRef>,
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

pub struct NewSession<S: AsyncRead + AsyncWrite> {
    c: Connection<S>,
    handle: Handle,
}

impl<S: AsyncRead + AsyncWrite + 'static> NewSession<S> {
    pub fn authenticate_key(
        self,
        user: &str,
        key: thrussh_keys::key::KeyPair,
    ) -> Box<Future<Item = Session<S>, Error = thrussh::HandlerError<()>>>
    where
        S: thrussh::Tcp,
    {
        let NewSession { c, handle } = self;
        Box::new(
            c.c
                .authenticate_key(user, key)
                .map(move |c| Session::make(Connection { c, task: None }, handle)),
        )
    }
}

pub struct Session<S: AsyncRead + AsyncWrite>(SharableConnection<S>);

impl<S: AsyncRead + AsyncWrite + thrussh::Tcp + 'static> Session<S> {
    pub fn new(stream: S, handle: &Handle) -> Result<NewSession<S>, thrussh::HandlerError<()>> {
        use std::sync::Arc;

        thrussh::client::Connection::new(Arc::default(), stream, SessionStateRef::default(), None)
            .map(|c| NewSession {
                c: Connection { c, task: None },
                handle: handle.clone(),
            })
            .map_err(thrussh::HandlerError::Error)
    }

    fn make(c: Connection<S>, handle: Handle) -> Self {
        let c = SharableConnection(Rc::new(RefCell::new(c)));
        handle.spawn(c.clone());
        Session(c)
    }

    pub fn last_error(&mut self) -> Option<thrussh::HandlerError<()>> {
        let connection = (self.0).0.borrow();
        let handler = connection.c.handler();
        let mut state = handler.0.borrow_mut();
        state.errored_with.take()
    }

    pub fn open_exec<'a>(&mut self, cmd: &'a str) -> ChannelOpenFuture<'a, S> {
        let mut session = (self.0).0.borrow_mut();
        let state = session.c.handler().clone();

        let channel_id = (&mut *session.c)
            .channel_open_session()
            .expect("sessions are always authenticated");
        state
            .borrow_mut()
            .state_for
            .insert(channel_id, ChannelState::default());
        ChannelOpenFuture {
            cmd,
            state,
            session: self.0.clone(),
            id: channel_id,
            first_round: true,
        }
    }
}

pub struct ChannelOpenFuture<'a, S: AsyncRead + AsyncWrite> {
    cmd: &'a str,
    session: SharableConnection<S>,
    state: SessionStateRef,
    id: thrussh::ChannelId,
    first_round: bool,
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

pub struct Channel {
    state: SessionStateRef,
    id: thrussh::ChannelId,
}

pub struct ExitStatusFuture {
    state: SessionStateRef,
    id: thrussh::ChannelId,
}

impl Channel {
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

use std::io::prelude::*;
use std::io;

struct ChannelState {
    closed: bool,

    read_notify: Option<futures::task::Task>,
    data_start: usize,
    data: Vec<u8>,
    eof: bool,

    exit_notify: Option<futures::task::Task>,
    exit_status: Option<u32>,

    open_notify: Option<futures::task::Task>,
    open_state: Option<Result<(), thrussh::ChannelOpenFailure>>,
}

impl Default for ChannelState {
    fn default() -> Self {
        ChannelState {
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

impl Read for Channel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut s = self.state.borrow_mut();
        let state = s.state_for
            .get_mut(&self.id)
            .expect("no state entry for valid channel");
        let n = ::std::cmp::min(buf.len(), state.data.len() - state.data_start);
        (&mut buf[..n]).copy_from_slice(&state.data[state.data_start..(state.data_start + n)]);

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
