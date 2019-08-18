use super::tokio_tls;
use super::tokio_tls::client;
use super::tokio_tls::common::Stream;
use super::tokio_tls::entry;
use super::tokio_tls::server;
use crate::tokio_tls::server::MidHandshake;
use core::fmt::Pointer;
use futures::{Async, Future, Poll};
use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession};
use std::error;
use std::fmt;
use std::io::{Error, ErrorKind};
use std::result;
use std::sync::Arc;
use std::{io, mem};
use webpki::DNSNameRef;

pub struct Error(io::Error);

impl error::Error for Error {
    fn description(&self) -> &str {
        error::Error::description(&self.0)
    }

    fn cause(&self) -> Option<&error::Error> {
        error::Error::cause(&self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error(error)
    }
}

pub enum HandshakeError<S> {
    Failure(Error),
    WouldBlock(MidHandshakeTlsStream<S>),
}

pub enum MidHandshakeTlsStream<S> {
    Server(server::MidHandshake<S>),
    Client(client::MidHandshake<S>),
}

impl<S> MidHandshakeTlsStream<S>
where
    S: io::Read + io::Write,
{
    /// Restarts the handshake process.
    ///
    /// If the handshake completes successfully then the negotiated stream is
    /// returned. If there is a problem, however, then an error is returned.
    /// Note that the error may not be fatal. For example if the underlying
    /// stream is an asynchronous one then `HandshakeError::WouldBlock` may
    /// just mean to wait for more I/O to happen later.
    pub fn handshake(self) -> result::Result<TlsStream<S>, HandshakeError<S>> {
        match self {
            MidHandshakeTlsStream::Server(s) => {
                if let MidHandshake::Handshaking(ref mut stream) = s {
                    let state = stream.state;
                    let (io, session) = stream.get_mut();
                    let mut stream = Stream::new(io, session).set_eof(!state.readable());

                    if stream.session.is_handshaking() {
                        match stream.complete_io() {
                            Ok(t) => t,
                            Err(ref e) if e.kind() == ::std::io::ErrorKind::WouldBlock => {
                                return HandshakeError::WouldBlock(stream);
                            }
                            Err(e) => return HandshakeError::Failure(Err(e.into())),
                        }
                    }

                    if stream.session.wants_write() {
                        match stream.complete_io() {
                            Ok(t) => t,
                            Err(ref e) if e.kind() == ::std::io::ErrorKind::WouldBlock => {
                                return HandshakeError::WouldBlock(stream);
                            }
                            Err(e) => return HandshakeError::Failure(Err(e.into())),
                        }
                    }
                }
                match mem::replace(self, MidHandshake::End) {
                    MidHandshake::Handshaking(stream) => stream,
                    MidHandshake::End => panic!(),
                }
            }
            MidHandshakeTlsStream::Client(s) => {
                if let client::MidHandshake::Handshaking(ref mut stream) = s {
                    let state = stream.state;
                    let (io, session) = stream.get_mut();
                    let mut stream = Stream::new(io, session).set_eof(!state.readable());

                    if stream.session.is_handshaking() {
                        match stream.complete_io() {
                            Ok(t) => t,
                            Err(ref e) if e.kind() == ::std::io::ErrorKind::WouldBlock => {
                                return Ok(::futures::Async::NotReady);
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }

                    if stream.session.wants_write() {
                        match stream.complete_io() {
                            Ok(t) => t,
                            Err(ref e) if e.kind() == ::std::io::ErrorKind::WouldBlock => {
                                return Ok(::futures::Async::NotReady);
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                }

                match mem::replace(self, client::MidHandshake::End) {
                    client::MidHandshake::Handshaking(stream) => stream,
                    #[cfg(feature = "early-data")]
                    client::MidHandshake::EarlyData(stream) => stream,
                    client::MidHandshake::End => panic!(),
                }
            }
        }
    }
}

pub struct TlsConnector {
    connector: entry::TlsConnector,
}

pub struct TlsConnectorBuilder {}

impl TlsConnectorBuilder {
    pub fn new(identity: Identity) -> Result<TlsConnector, Error> {
        match identity {
            Identity::Client(s) => Ok(TlsConnector {
                connector: entry::TlsConnector::from(s),
            }),
            _ => Err(io::Error::new(ErrorKind::Other, "oh no!")),
        }
    }
}

impl TlsConnector {
    pub fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> result::Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let domain = webpki::DNSNameRef::try_from_ascii_str(domain).map_err(|err| {
            HandshakeError::Failure(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid domain name ({}): {}", err, domain),
            ))
        })?;
        let mut session = ClientSession::new(&self.connector.inner, domain);
        MidHandshakeTlsStream::Client(client::MidHandshake::Handshaking(client::TlsStream {
            session,
            io: stream,
            state: entry::TlsState::Stream,
        }))
        .handshake()
    }
}

pub struct TlsAcceptor {
    acceptor: entry::TlsAcceptor,
}

impl TlsAcceptor {
    pub fn accept<S>(&self, stream: S) -> MidHandshakeTlsStream<S>
    where
        S: io::Read + io::Write,
    {
        let mut session = ServerSession::new(&self.acceptor.inner);

        MidHandshakeTlsStream::Server(server::MidHandshake::Handshaking(server::TlsStream {
            session,
            io: stream,
            state: entry::TlsState::Stream,
        }))
        .handshake()
    }
}

pub struct TlsAcceptorBuilder {}

impl TlsAcceptorBuilder {
    pub fn new(identity: Identity) -> Result<TlsAcceptor, Error> {
        match identity {
            Identity::Server(s) => Ok(TlsAcceptor {
                acceptor: (entry::TlsAcceptor::from(s)),
            }),
            _ => Err(io::Error::new(ErrorKind::Other, "oh no!")),
        }
    }
}

/// A stream managing a TLS session.
pub struct TlsStream<S>(imp::TlsStream<S>);

pub struct TlsSession(imp::TlsSession);

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: io::Read + io::Write> TlsStream<S> {
    /// Shuts down the TLS session.
    pub fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.0.shutdown()
    }
}

impl<S: io::Read + io::Write> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
