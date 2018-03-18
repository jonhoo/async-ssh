use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;
use futures;
use thrussh_keys;
use thrussh;
use channel;

#[derive(Default)]
pub(crate) struct Inner {
    pub(crate) state_for: HashMap<thrussh::ChannelId, channel::State>,
    pub(crate) errored_with: Option<thrussh::HandlerError<()>>,
}

#[derive(Default, Clone)]
pub(crate) struct Ref(Rc<RefCell<Inner>>);

impl Deref for Ref {
    type Target = Rc<RefCell<Inner>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl thrussh::client::Handler for Ref {
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
