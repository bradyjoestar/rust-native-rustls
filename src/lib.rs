#[path = "imp/rustls.rs"]
mod imp;

mod tokio_tls;

extern crate tokio_io;
use tokio_io::{try_nb, AsyncRead, AsyncWrite};

use futures::{Future, Poll};
use std::fmt;
use std::io;
use std::result;
use tokio_tls::client;
use tokio_tls::server;

pub struct Identity(imp::Identity);

pub struct MidHandshakeTlsStream<S>(imp::MidHandshakeTlsStream<S>);

impl<S: AsyncRead + AsyncWrite> Future for MidHandshakeTlsStream<S> {
    type Item = imp::TlsStream<S>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

pub struct TlsConnector(imp::TlsConnector);

impl TlsConnector {
    pub fn new(identity: imp::Identity) -> Result<TlsConnector, io::Error> {
        Ok(TlsConnector(
            imp::TlsConnectorBuilder::new(identity).unwrap(),
        ))
    }
}

pub struct TlsAcceptor(imp::TlsAcceptor);

impl TlsAcceptor {
    pub fn new(identity: imp::Identity) -> Result<TlsAcceptor, io::Error> {
        Ok(TlsAcceptor(imp::TlsAcceptorBuilder::new(identity).unwrap()))
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

impl<S: AsyncRead + AsyncWrite> TlsStream<S> {
    /// Shuts down the TLS session.
    pub fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.0.shutdown()
    }
}

impl<S: AsyncRead + AsyncWrite> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: AsyncRead + AsyncWrite> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
