extern crate async_ssh;
extern crate futures;
extern crate thrussh;
extern crate thrussh_keys;
extern crate tokio_core;
extern crate tokio_io;

use std::io::prelude::*;
use tokio_core::net::TcpStream;
use async_ssh::Session;
use futures::Future;

fn main() {
    // async:

    let mut core = tokio_core::reactor::Core::new().unwrap();
    let handle = core.handle();

    let cmd = ::std::env::args().skip(1).next().unwrap();
    let key = thrussh_keys::load_secret_key("/home/jon/aws-test.pem", None).unwrap();

    let ls_out = TcpStream::connect(&"52.23.157.12:22".parse().unwrap(), &handle)
        .map_err(thrussh::Error::IO)
        .map_err(thrussh::HandlerError::Error)
        .and_then(|c| Session::new(c, &handle))
        .and_then(|session| session.authenticate_key("ec2-user", key))
        .and_then(|mut session| session.open_exec(&cmd));

    let channel = core.run(ls_out).unwrap();
    let (channel, data) = core.run(tokio_io::io::read_to_end(channel, Vec::new()))
        .unwrap();
    println!("{}", ::std::str::from_utf8(&data[..]).unwrap());
    let status = core.run(channel.exit_status()).unwrap();
    println!("{}", status);

    /*

    // sync:

    // Connect to the local SSH server
    let tcp = TcpStream::connect("127.0.0.1:22").unwrap();
    let mut sess = Session::new().unwrap();
    sess.handshake(&tcp).unwrap();
    sess.userauth_agent("username").unwrap();

    let mut channel = sess.channel_session().unwrap();
    channel.exec("ls").unwrap();
    let mut s = String::new();
    channel.read_to_string(&mut s).unwrap();
    println!("{}", s);
    channel.wait_close();
    println!("{}", channel.exit_status().unwrap());
    */
}
