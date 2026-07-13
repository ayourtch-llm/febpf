//! Provider-neutral packet ownership for XDP execution.
//!
//! Providers transfer owned frames into febpf and receive each completed
//! frame back with either its verdict or its runtime error. Guest programs
//! only see febpf virtual addresses for the active data window; provider
//! storage addresses are never exposed.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::EbpfError;

/// An owned packet buffer with an explicit active data window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XdpFrame {
    storage: Vec<u8>,
    data_start: usize,
    data_end: usize,
    metadata: XdpMetadata,
    cookie: u64,
}

impl XdpFrame {
    /// Copy packet bytes into a frame with no spare capacity.
    pub fn new(packet: &[u8]) -> Self {
        Self {
            storage: packet.to_vec(),
            data_start: 0,
            data_end: packet.len(),
            metadata: XdpMetadata::default(),
            cookie: 0,
        }
    }

    /// Adopt provider storage and an active data window without copying it.
    pub fn from_storage(
        storage: Vec<u8>,
        data_start: usize,
        data_end: usize,
    ) -> Result<Self, String> {
        if data_start > data_end || data_end > storage.len() {
            return Err("XDP data window lies outside frame storage".into());
        }
        Ok(Self {
            storage,
            data_start,
            data_end,
            metadata: XdpMetadata::default(),
            cookie: 0,
        })
    }

    /// Copy packet bytes into a frame with zero-filled space on both sides.
    pub fn with_capacity(packet: &[u8], headroom: usize, tailroom: usize) -> Result<Self, String> {
        let data_end = headroom
            .checked_add(packet.len())
            .ok_or_else(|| "XDP frame capacity overflows address space".to_string())?;
        let capacity = data_end
            .checked_add(tailroom)
            .ok_or_else(|| "XDP frame capacity overflows address space".to_string())?;
        let mut storage = vec![0; capacity];
        storage[headroom..data_end].copy_from_slice(packet);
        Self::from_storage(storage, headroom, data_end)
    }

    /// Bytes visible to the XDP program.
    pub fn data(&self) -> &[u8] {
        &self.storage[self.data_start..self.data_end]
    }

    /// Mutable bytes visible to the XDP program.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.storage[self.data_start..self.data_end]
    }

    pub fn headroom(&self) -> usize {
        self.data_start
    }

    pub fn tailroom(&self) -> usize {
        self.storage.len() - self.data_end
    }

    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Synthetic non-pointer fields installed in `xdp_md`.
    pub fn metadata(&self) -> XdpMetadata {
        self.metadata
    }

    pub fn set_metadata(&mut self, metadata: XdpMetadata) {
        self.metadata = metadata;
    }

    /// Opaque provider token carried through execution unchanged.
    pub fn cookie(&self) -> u64 {
        self.cookie
    }

    pub fn set_cookie(&mut self, cookie: u64) {
        self.cookie = cookie;
    }

    /// Return the backing allocation and active window to the provider.
    pub fn into_storage(self) -> (Vec<u8>, usize, usize) {
        (self.storage, self.data_start, self.data_end)
    }
}

/// Provider-supplied scalar fields for febpf's synthetic `xdp_md`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpMetadata {
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

/// A recognized Linux XDP action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum XdpAction {
    Aborted = 0,
    Drop = 1,
    Pass = 2,
    Tx = 3,
    Redirect = 4,
}

impl XdpAction {
    pub fn from_return_value(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Aborted),
            1 => Some(Self::Drop),
            2 => Some(Self::Pass),
            3 => Some(Self::Tx),
            4 => Some(Self::Redirect),
            _ => None,
        }
    }
}

/// The raw program return value and its recognized XDP interpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XdpVerdict {
    pub return_value: u64,
    pub action: Option<XdpAction>,
}

impl XdpVerdict {
    pub fn new(return_value: u64) -> Self {
        Self {
            return_value,
            action: XdpAction::from_return_value(return_value),
        }
    }
}

/// A frame returned to its provider after one VM invocation.
#[derive(Debug)]
pub struct CompletedXdpFrame {
    pub frame: XdpFrame,
    pub result: Result<XdpVerdict, EbpfError>,
}

/// Transport boundary between packet I/O and febpf's XDP engine.
pub trait XdpProvider {
    type Error;

    /// Transfer the next owned frame to febpf, or return `None` when the
    /// provider currently has no more work.
    fn receive(&mut self) -> Result<Option<XdpFrame>, Self::Error>;

    /// Reclaim a frame after execution. Runtime failures are delivered here
    /// as data and do not turn into provider transport failures.
    fn complete(&mut self, completed: CompletedXdpFrame) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpBatchStats {
    pub received: usize,
    pub completed: usize,
    pub runtime_errors: usize,
}

/// Which provider operation failed while processing a bounded batch.
#[derive(Debug)]
pub enum XdpProviderError<E> {
    Receive(E),
    Complete(E),
}
