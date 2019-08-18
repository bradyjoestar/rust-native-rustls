#[path = "imp/rustls-sync.rs"]
mod imp;

#[path = "imp/rustls.rs"]
mod imple;

mod tokio_tls;

extern crate tokio_io;
use tokio_io::{try_nb, AsyncRead, AsyncWrite};

use futures::{Future, Poll};
use std::any::Any;
use std::error;
use std::fmt;
use std::io;
use std::result;
use tokio_tls::client;
use tokio_tls::server;
use webpki::DNSNameRef;

pub struct Identity(imp::Identity);

/// A typedef of the result-type returned by many methods.
pub type Result<T> = result::Result<T, Error>;

/// An error returned from the TLS implementation.
pub struct Error(imp::Error);

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

impl From<imp::Error> for Error {
    fn from(err: imp::Error) -> Error {
        Error(err)
    }
}

/// An error returned from `ClientBuilder::handshake`.
#[derive(Debug)]
pub enum HandshakeError<S> {
    /// A fatal error.
    Failure(Error),

    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    ///
    /// Note that this is not a fatal error and it should be safe to call
    /// `handshake` at a later time once the stream is ready to perform I/O
    /// again.
    WouldBlock(MidHandshakeTlsStream<S>),
}

impl<S> error::Error for HandshakeError<S>
where
    S: Any + fmt::Debug,
{
    fn description(&self) -> &str {
        "handshake error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            HandshakeError::Failure(ref e) => Some(e),
            HandshakeError::WouldBlock(_) => None,
        }
    }
}

impl<S> fmt::Display for HandshakeError<S>
where
    S: Any + fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HandshakeError::Failure(ref e) => fmt::Display::fmt(e, fmt),
            HandshakeError::WouldBlock(_) => fmt.write_str("the handshake process was interrupted"),
        }
    }
}

impl<S> From<imp::HandshakeError<S>> for HandshakeError<S> {
    fn from(e: imp::HandshakeError<S>) -> HandshakeError<S> {
        match e {
            imp::HandshakeError::Failure(e) => HandshakeError::Failure(Error(e)),
            imp::HandshakeError::WouldBlock(s) => {
                HandshakeError::WouldBlock(MidHandshakeTlsStream(s))
            }
        }
    }
}

pub struct MidHandshakeTlsStream<S>(imp::MidHandshakeTlsStream<S>);

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
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
        match self.0.handshake() {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

pub struct TlsConnector(imp::TlsConnector);

impl TlsConnector {
    pub fn new(identity: imp::Identity) -> Result<TlsConnector> {
        Ok(TlsConnector(
            imp::TlsConnectorBuilder::new(identity).unwrap(),
        ))
    }

    /// Initiates a TLS handshake.
    ///
    /// The provided domain will be used for both SNI and certificate hostname
    /// validation.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::WouldBlock` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    ///
    /// The domain is ignored if both SNI and hostname verification are
    /// disabled.
    pub fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> result::Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let s = self.0.connect(domain, stream)?;
        Ok(TlsStream(s))
    }
}

pub struct TlsAcceptor(imp::TlsAcceptor);

impl TlsAcceptor {
    pub fn new(identity: imp::Identity) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor(imp::TlsAcceptorBuilder::new(identity).unwrap()))
    }

    pub fn accept<S>(&self, stream: S) -> MidHandshakeTlsStream<S>
    where
        S: AsyncRead + AsyncWrite,
    {
        MidHandshakeTlsStream(self.0.accept(stream))
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
