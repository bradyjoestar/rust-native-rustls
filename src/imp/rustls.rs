//use tokio_io::{try_nb, AsyncRead, AsyncWrite};
//
//use super::tokio_tls;
//use super::tokio_tls::client;
//use super::tokio_tls::entry;
//use super::tokio_tls::server;
//use core::fmt::Pointer;
//use futures::{Async, Future, Poll};
//use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Stream};
//use std::fmt;
//use std::io::{Error, ErrorKind};
//use std::result;
//use std::sync::Arc;
//use std::{io, mem};
//use webpki::DNSNameRef;
//
//pub enum Identity {
//    Server(Arc<ServerConfig>),
//    Client(Arc<ClientConfig>),
//}
//
//pub enum MidHandshakeTlsStream<S> {
//    Server(server::MidHandshake<S>),
//    Client(client::MidHandshake<S>),
//}
//
//impl<S: AsyncRead + AsyncWrite> Future for MidHandshakeTlsStream<S> {
//    type Item = TlsStream<S>;
//    type Error = io::Error;
//
//    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
//        match self {
//            MidHandshakeTlsStream::Server(s) => match s.poll() {
//                Ok(t) => match t {
//                    Async::Ready(r) => Ok(Async::Ready(TlsStream::Server(r))),
//                    Async::NotReady => Ok(Async::NotReady),
//                },
//
//                Err(e) => Err(e),
//            },
//            MidHandshakeTlsStream::Client(s) => match s.poll() {
//                Ok(t) => match t {
//                    Async::Ready(r) => Ok(Async::Ready(TlsStream::Client(r))),
//                    Async::NotReady => Ok(Async::NotReady),
//                },
//                Err(e) => Err(e),
//            },
//        }
//    }
//}
//
//pub struct TlsConnector {
//    connector: entry::TlsConnector,
//}
//
//pub struct TlsConnectorBuilder {}
//
//impl TlsConnectorBuilder {
//    pub fn new(identity: Identity) -> Result<TlsConnector, Error> {
//        match identity {
//            Identity::Client(s) => Ok(TlsConnector {
//                connector: entry::TlsConnector::from(s),
//            }),
//            _ => Err(io::Error::new(ErrorKind::Other, "oh no!")),
//        }
//    }
//}
//
//impl TlsConnector {
//    pub fn connect<S>(&self, domain: DNSNameRef, stream: S) -> MidHandshakeTlsStream<S>
//    where
//        S: AsyncRead + AsyncWrite,
//    {
//        let mut session = ClientSession::new(&self.connector.inner, domain);
//        MidHandshakeTlsStream::Client(client::MidHandshake::Handshaking(client::TlsStream {
//            session,
//            io: stream,
//            state: entry::TlsState::Stream,
//        }))
//    }
//}
//
//pub struct TlsAcceptor {
//    acceptor: entry::TlsAcceptor,
//}
//
//impl TlsAcceptor {
//    pub fn accept<S>(&self, stream: S) -> MidHandshakeTlsStream<S>
//    where
//        S: AsyncRead + AsyncWrite,
//    {
//        let mut session = ServerSession::new(&self.acceptor.inner);
//
//        MidHandshakeTlsStream::Server(server::MidHandshake::Handshaking(server::TlsStream {
//            session,
//            io: stream,
//            state: entry::TlsState::Stream,
//        }))
//    }
//}
//
//pub struct TlsAcceptorBuilder {}
//
//impl TlsAcceptorBuilder {
//    pub fn new(identity: Identity) -> Result<TlsAcceptor, Error> {
//        match identity {
//            Identity::Server(s) => Ok(TlsAcceptor {
//                acceptor: (entry::TlsAcceptor::from(s)),
//            }),
//            _ => Err(io::Error::new(ErrorKind::Other, "oh no!")),
//        }
//    }
//}
//
//pub enum TlsStream<S> {
//    Server(server::TlsStream<S>),
//    Client(client::TlsStream<S>),
//}
//
//pub enum TlsSession {
//    Server(ServerSession),
//    Client(ClientSession),
//}
//
//impl<S> fmt::Debug for TlsStream<S>
//where
//    S: fmt::Debug,
//{
//    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
//        match *self {
//            TlsStream::Server(ref s) => s.fmt(fmt),
//            TlsStream::Client(ref s) => s.fmt(fmt),
//        }
//    }
//}
//
//impl<S: AsyncRead + AsyncWrite> TlsStream<S> {
//    /// Shuts down the TLS session.
//    pub fn shutdown(&mut self) -> Poll<(), io::Error> {
//        match *self {
//            TlsStream::Server(ref mut s) => s.shutdown(),
//            TlsStream::Client(ref mut s) => s.shutdown(),
//        }
//    }
//}
//
//impl<S: AsyncRead + AsyncWrite> io::Read for TlsStream<S> {
//    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//        match *self {
//            TlsStream::Server(ref mut s) => s.read(buf),
//            TlsStream::Client(ref mut s) => s.read(buf),
//        }
//    }
//}
//
//impl<S: AsyncRead + AsyncWrite> io::Write for TlsStream<S> {
//    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
//        match *self {
//            TlsStream::Server(ref mut s) => s.write(buf),
//            TlsStream::Client(ref mut s) => s.write(buf),
//        }
//    }
//
//    fn flush(&mut self) -> io::Result<()> {
//        match *self {
//            TlsStream::Server(ref mut s) => s.flush(),
//            TlsStream::Client(ref mut s) => s.flush(),
//        }
//    }
//}
