extern crate futures;
extern crate thrussh;
extern crate thrussh_keys;
extern crate tokio_io;

use tokio_io::{AsyncRead, AsyncWrite};
use std::rc::Rc;
use std::cell::RefCell;
use futures::Future;
use std::collections::HashMap;

#[derive(Default)]
struct SessionState {
    state_for: HashMap<thrussh::ChannelId, ChannelState>,
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
            if let Some(task) = state.notify.take() {
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

            state.finished = true;
            if let Some(task) = state.notify.take() {
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

            state.finished = true;
            if let Some(task) = state.notify.take() {
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
            state
                .state_for
                .get_mut(&channel)
                .expect("got data for unknown channel")
                .exit_status = Some(exit_status);

            // TODO: wake up ExitStatusFuture
        }

        futures::finished((self, session))
    }
}

pub struct NewSession<S: AsyncRead + AsyncWrite>(thrussh::client::Connection<S, SessionStateRef>);

impl<S: AsyncRead + AsyncWrite + 'static> NewSession<S> {
    pub fn authenticate_key(
        self,
        user: &str,
        key: thrussh_keys::key::KeyPair,
    ) -> Box<Future<Item = Session<S>, Error = thrussh::HandlerError<()>>>
    where
        S: thrussh::Tcp,
    {
        Box::new(self.0.authenticate_key(user, key).map(Session))
    }
}

pub struct Session<S: AsyncRead + AsyncWrite>(thrussh::client::Connection<S, SessionStateRef>);

impl<S: AsyncRead + AsyncWrite + 'static> Session<S> {
    pub fn new(stream: S) -> Result<NewSession<S>, thrussh::HandlerError<()>> {
        use std::sync::Arc;

        thrussh::client::Connection::new(Arc::default(), stream, SessionStateRef::default(), None)
            .map(NewSession)
            .map_err(thrussh::HandlerError::Error)
    }

    pub fn open_exec<'a>(
        self,
        cmd: &'a str,
    ) -> Box<Future<Item = (Session<S>, Channel), Error = thrussh::HandlerError<()>> + 'a>
    where
        S: thrussh::Tcp,
    {
        Box::new(
            self.0
                .channel_open_session()
                .map(move |(mut c, channel_id)| {
                    c.exec(channel_id, true, cmd);
                    let state = c.handler().clone();
                    state
                        .borrow_mut()
                        .state_for
                        .insert(channel_id, ChannelState::default());
                    let channel = Channel {
                        state: c.handler().clone(),
                        id: channel_id,
                    };
                    (Session(c), channel)
                }),
        )
    }
}

impl<S: AsyncRead + AsyncWrite + thrussh::Tcp> Future for Session<S> {
    type Item = ();
    type Error = thrussh::HandlerError<()>;

    fn poll(&mut self) -> futures::Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

pub struct Channel {
    state: SessionStateRef,
    id: thrussh::ChannelId,
}

impl Channel {
    //pub fn exit_status(self) -> Box<Future<Item = u32, Error = ()>> {}
}

use std::io::prelude::*;
use std::io;

struct ChannelState {
    data_start: usize,
    data: Vec<u8>,
    finished: bool,
    notify: Option<futures::task::Task>,
    exit_status: Option<u32>,
}

impl Default for ChannelState {
    fn default() -> Self {
        ChannelState {
            data_start: 0,
            data: Vec::new(),
            finished: false,
            notify: None,
            exit_status: None,
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

        if n == 0 && !state.finished {
            state.notify = Some(futures::task::current());
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
