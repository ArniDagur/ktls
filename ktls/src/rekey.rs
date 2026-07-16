//! TLS 1.3 rekeying (RFC 8446 §4.6.3 KeyUpdate) for kTLS sockets.
//!
//! Linux 6.13+ allows updating a kTLS socket's keys with a second
//! `setsockopt(SOL_TLS, TLS_RX/TLS_TX)`. Key derivation is done by rustls:
//! [`rustls::kernel::KernelConnection`] retains the connection's key
//! schedule after the handshake and computes each generation's traffic
//! secrets, so no key material is ever ratcheted in this crate.

use std::io;
use std::os::unix::prelude::RawFd;

use rustls::client::ClientConnectionData;
use rustls::kernel::KernelConnection;
use rustls::server::ServerConnectionData;
use rustls::SupportedCipherSuite;

use crate::ffi::{self, CryptoInfo, Direction};

pub(crate) enum KernelConn {
    Client(KernelConnection<ClientConnectionData>),
    Server(KernelConnection<ServerConnectionData>),
}

impl KernelConn {
    pub(crate) fn negotiated_cipher_suite(&self) -> SupportedCipherSuite {
        match self {
            KernelConn::Client(c) => c.negotiated_cipher_suite(),
            KernelConn::Server(c) => c.negotiated_cipher_suite(),
        }
    }

    fn update_tx_secret(
        &mut self,
    ) -> Result<(u64, rustls::ConnectionTrafficSecrets), rustls::Error> {
        match self {
            KernelConn::Client(c) => c.update_tx_secret(),
            KernelConn::Server(c) => c.update_tx_secret(),
        }
    }

    fn update_rx_secret(
        &mut self,
    ) -> Result<(u64, rustls::ConnectionTrafficSecrets), rustls::Error> {
        match self {
            KernelConn::Client(c) => c.update_rx_secret(),
            KernelConn::Server(c) => c.update_rx_secret(),
        }
    }
}

/// KeyUpdate message: msg_type(24) len(1) request_update(update_not_requested).
const KEY_UPDATE_NOT_REQUESTED: [u8; 5] = [24, 0, 0, 1, 0];

/// Per-connection rekey state.
pub(crate) struct RekeyState {
    conn: KernelConn,
    suite: SupportedCipherSuite,
    /// Our KeyUpdate reply + TX key switch is still owed (the peer sent
    /// `update_requested` but the send buffer was full).
    pub(crate) pending_tx: bool,
}

impl std::fmt::Debug for RekeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RekeyState")
            .field("suite", &self.suite)
            .field("pending_tx", &self.pending_tx)
            .finish_non_exhaustive()
    }
}

impl RekeyState {
    pub(crate) fn new(conn: KernelConn, suite: SupportedCipherSuite) -> Self {
        Self {
            conn,
            suite,
            pending_tx: false,
        }
    }

    /// The peer rekeyed: install its next-generation key for RX.
    pub(crate) fn rekey_rx(&mut self, fd: RawFd) -> io::Result<()> {
        let pair = self
            .conn
            .update_rx_secret()
            .map_err(io::Error::other)?;
        let info = CryptoInfo::from_rustls(self.suite, pair).map_err(io::Error::other)?;
        ffi::set_tls_info(fd, Direction::Rx, info)
    }

    /// Answer `update_requested`: send our KeyUpdate as the last record under
    /// the old TX key, then switch TX to the next generation.
    pub(crate) fn rekey_tx(&mut self, fd: RawFd) -> io::Result<()> {
        ffi::send_handshake_record(fd, &KEY_UPDATE_NOT_REQUESTED)?;
        let pair = self
            .conn
            .update_tx_secret()
            .map_err(io::Error::other)?;
        let info = CryptoInfo::from_rustls(self.suite, pair).map_err(io::Error::other)?;
        ffi::set_tls_info(fd, Direction::Tx, info)?;
        self.pending_tx = false;
        Ok(())
    }
}
