//! Linux AF_XDP copy-mode adapter for [`crate::packet::XdpProvider`].
//!
//! Socket, UMEM, and ring lifetimes are deliberately confined to this module.
//! The VM receives ordinary owned [`XdpFrame`] values and never observes an
//! AF_XDP descriptor or host pointer.

use crate::packet::{
    CompletedXdpFrame, XdpAction, XdpCapabilities, XdpFrame, XdpMetadata, XdpProvider, XdpRedirect,
};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_int, c_void};
use core::mem::{size_of, zeroed};
use core::ptr::{copy_nonoverlapping, null, null_mut};
use core::sync::atomic::{AtomicU32, Ordering};
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const AF_XDP: c_int = 44;
const SOCK_RAW: c_int = 3;
const SOCK_NONBLOCK: c_int = 0x800;
const SOCK_CLOEXEC: c_int = 0x80000;
const SOL_XDP: c_int = 283;

const XDP_MMAP_OFFSETS: c_int = 1;
const XDP_RX_RING: c_int = 2;
const XDP_TX_RING: c_int = 3;
const XDP_UMEM_REG: c_int = 4;
const XDP_UMEM_FILL_RING: c_int = 5;
const XDP_UMEM_COMPLETION_RING: c_int = 6;

const XDP_COPY: u16 = 1 << 1;
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;
const XDP_RING_NEED_WAKEUP: u32 = 1;

const XDP_PGOFF_RX_RING: i64 = 0;
const XDP_PGOFF_TX_RING: i64 = 0x8000_0000;
const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x1_0000_0000;
const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x1_8000_0000;

const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_SHARED: c_int = 1;
const MAP_PRIVATE: c_int = 2;
const MAP_ANONYMOUS: c_int = 0x20;
const MSG_DONTWAIT: c_int = 0x40;
const POLLIN: i16 = 0x0001;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fill: XdpRingOffset,
    completion: XdpRingOffset,
}

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

#[repr(C)]
struct SockAddrXdp {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue_id: u32,
    shared_umem_fd: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, len: u32) -> c_int;
    fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut c_void, len: *mut u32)
        -> c_int;
    fn bind(fd: c_int, address: *const c_void, len: u32) -> c_int;
    fn mmap(
        address: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, len: usize) -> c_int;
    fn sendto(
        fd: c_int,
        buffer: *const c_void,
        len: usize,
        flags: c_int,
        address: *const c_void,
        address_len: u32,
    ) -> isize;
    fn poll(fds: *mut PollFd, count: usize, timeout_ms: c_int) -> c_int;
    fn if_nametoindex(name: *const u8) -> u32;
}

/// What the adapter should do with `XDP_PASS` after AF_XDP has already taken
/// the packet out of the kernel receive path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PassDisposition {
    /// Consume the packet and return its UMEM frame to the fill ring.
    #[default]
    Recycle,
    /// Re-inject the packet through this socket's TX ring.
    Transmit,
}

/// Configuration for one copy-mode socket and its private UMEM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AfXdpConfig {
    pub ifindex: u32,
    pub queue_id: u32,
    pub frame_count: u32,
    pub frame_size: u32,
    pub frame_headroom: u32,
    pub pass: PassDisposition,
}

impl AfXdpConfig {
    pub fn new(ifindex: u32, queue_id: u32) -> Self {
        Self {
            ifindex,
            queue_id,
            frame_count: 256,
            frame_size: 4096,
            frame_headroom: 256,
            pass: PassDisposition::Recycle,
        }
    }

    pub fn validate(&self) -> Result<(), AfXdpError> {
        if self.ifindex == 0 {
            return Err(AfXdpError::InvalidConfig("ifindex must be nonzero".into()));
        }
        if !self.frame_count.is_power_of_two() || self.frame_count < 2 {
            return Err(AfXdpError::InvalidConfig(
                "frame_count must be a power of two and at least 2".into(),
            ));
        }
        if !matches!(self.frame_size, 2048 | 4096) {
            return Err(AfXdpError::InvalidConfig(
                "frame_size must be 2048 or 4096 in aligned-chunk mode".into(),
            ));
        }
        if self.frame_headroom >= self.frame_size {
            return Err(AfXdpError::InvalidConfig(
                "frame_headroom must be smaller than frame_size".into(),
            ));
        }
        (self.frame_count as usize)
            .checked_mul(self.frame_size as usize)
            .ok_or_else(|| AfXdpError::InvalidConfig("UMEM length overflows usize".into()))?;
        Ok(())
    }
}

/// Resolve an interface name without adding a libc dependency.
pub fn interface_index(name: &str) -> Result<u32, AfXdpError> {
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(AfXdpError::InvalidConfig(
            "interface name must be nonempty and contain no NUL".into(),
        ));
    }
    let mut nul = Vec::with_capacity(name.len() + 1);
    nul.extend_from_slice(name.as_bytes());
    nul.push(0);
    // SAFETY: `nul` is a live NUL-terminated byte string for the duration of
    // the call.
    let index = unsafe { if_nametoindex(nul.as_ptr()) };
    if index == 0 {
        Err(AfXdpError::Io(io::Error::last_os_error()))
    } else {
        Ok(index)
    }
}

#[derive(Debug)]
pub enum AfXdpError {
    InvalidConfig(String),
    Io(io::Error),
    InvalidDescriptor { addr: u64, len: u32 },
    ForeignFrame(u64),
    TxRingFull,
    UnboundRedirect(XdpRedirect),
}

impl core::fmt::Display for AfXdpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid AF_XDP configuration: {message}"),
            Self::Io(error) => write!(f, "AF_XDP I/O error: {error}"),
            Self::InvalidDescriptor { addr, len } => {
                write!(
                    f,
                    "AF_XDP descriptor addr={addr} len={len} lies outside UMEM"
                )
            }
            Self::ForeignFrame(cookie) => {
                write!(
                    f,
                    "frame cookie {cookie} is not owned by this AF_XDP provider"
                )
            }
            Self::TxRingFull => write!(f, "AF_XDP TX ring is full"),
            Self::UnboundRedirect(destination) => {
                write!(
                    f,
                    "AF_XDP redirect destination is not provider-owned: {destination:?}"
                )
            }
        }
    }
}

impl std::error::Error for AfXdpError {}

impl From<io::Error> for AfXdpError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

struct Mapping {
    address: *mut u8,
    len: usize,
}

impl Mapping {
    fn anonymous(len: usize) -> Result<Self, AfXdpError> {
        // SAFETY: the arguments request a new private anonymous mapping. The
        // returned mapping is owned by `Self` and released exactly once.
        let address = unsafe {
            mmap(
                null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if address as isize == -1 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(Self {
                address: address.cast(),
                len,
            })
        }
    }

    fn shared(fd: c_int, len: usize, offset: i64) -> Result<Self, AfXdpError> {
        // SAFETY: the kernel owns the AF_XDP ring object at this fd/offset;
        // `Self` owns only this userspace mapping and unmaps it exactly once.
        let address = unsafe {
            mmap(
                null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd,
                offset,
            )
        };
        if address as isize == -1 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(Self {
                address: address.cast(),
                len,
            })
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `address..address+len` is the live mapping owned by `self`.
        unsafe {
            munmap(self.address.cast(), self.len);
        }
    }
}

struct Ring<T: Copy> {
    _mapping: Mapping,
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    flags: *mut AtomicU32,
    entries: *mut T,
    count: u32,
    mask: u32,
}

impl<T: Copy> Ring<T> {
    fn map(
        fd: c_int,
        offset: XdpRingOffset,
        count: u32,
        page_offset: i64,
    ) -> Result<Self, AfXdpError> {
        let entries_len = (count as usize)
            .checked_mul(size_of::<T>())
            .and_then(|bytes| (offset.desc as usize).checked_add(bytes))
            .ok_or_else(|| AfXdpError::InvalidConfig("ring mapping length overflows".into()))?;
        let flags_len = (offset.flags as usize)
            .checked_add(size_of::<u32>())
            .ok_or_else(|| AfXdpError::InvalidConfig("ring flags offset overflows".into()))?;
        let len = entries_len.max(flags_len);
        let mapping = Mapping::shared(fd, len, page_offset)?;
        let base = mapping.address;
        Ok(Self {
            // SAFETY: offsets are supplied by the kernel for this mapping and
            // the length above covers every field and descriptor.
            producer: unsafe { base.add(offset.producer as usize).cast() },
            // SAFETY: see `producer`.
            consumer: unsafe { base.add(offset.consumer as usize).cast() },
            // SAFETY: see `producer`.
            flags: unsafe { base.add(offset.flags as usize).cast() },
            // SAFETY: see `producer`.
            entries: unsafe { base.add(offset.desc as usize).cast() },
            _mapping: mapping,
            count,
            mask: count - 1,
        })
    }

    fn push(&mut self, value: T) -> bool {
        // SAFETY: producer/consumer point to kernel-provided, u32-aligned ring
        // counters for the lifetime of the mapping.
        let producer = unsafe { &*self.producer }.load(Ordering::Relaxed);
        // SAFETY: see above.
        let consumer = unsafe { &*self.consumer }.load(Ordering::Acquire);
        if producer.wrapping_sub(consumer) >= self.count {
            return false;
        }
        // SAFETY: this process is the ring's sole producer and the masked slot
        // is reserved until the release-store publishes it.
        unsafe {
            self.entries
                .add((producer & self.mask) as usize)
                .write(value);
            (&*self.producer).store(producer.wrapping_add(1), Ordering::Release);
        }
        true
    }

    fn pop(&mut self) -> Option<T> {
        // SAFETY: producer/consumer point to live ring counters.
        let consumer = unsafe { &*self.consumer }.load(Ordering::Relaxed);
        // SAFETY: see above.
        let producer = unsafe { &*self.producer }.load(Ordering::Acquire);
        if consumer == producer {
            return None;
        }
        // SAFETY: this process is the ring's sole consumer; the acquire-load
        // makes the published descriptor visible before it is read.
        let value = unsafe { self.entries.add((consumer & self.mask) as usize).read() };
        // SAFETY: see above.
        unsafe {
            (&*self.consumer).store(consumer.wrapping_add(1), Ordering::Release);
        }
        Some(value)
    }

    fn needs_wakeup(&self) -> bool {
        // SAFETY: flags points to the live ring flags word.
        unsafe { &*self.flags }.load(Ordering::Acquire) & XDP_RING_NEED_WAKEUP != 0
    }
}

/// One AF_XDP socket, its private UMEM, and the sparse virtual XSKMAP slots
/// that completion is allowed to deliver through this socket.
pub struct AfXdpProvider {
    config: AfXdpConfig,
    socket: OwnedFd,
    umem: Mapping,
    rx: Ring<XdpDesc>,
    tx: Ring<XdpDesc>,
    fill: Ring<u64>,
    completion: Ring<u64>,
    pending_fill: VecDeque<u64>,
    in_flight: BTreeMap<u64, u64>,
    next_cookie: u64,
    xskmap_slots: BTreeSet<(u32, u32)>,
}

impl AsRawFd for AfXdpProvider {
    fn as_raw_fd(&self) -> c_int {
        self.socket.as_raw_fd()
    }
}

impl AfXdpProvider {
    pub fn open(config: AfXdpConfig) -> Result<Self, AfXdpError> {
        config.validate()?;
        // SAFETY: `socket` is called with a Linux AF_XDP domain and returns a
        // fresh descriptor on success.
        let raw_fd = unsafe { socket(AF_XDP, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: raw_fd is freshly returned and uniquely owned here.
        let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let umem_len = config.frame_count as usize * config.frame_size as usize;
        let umem = Mapping::anonymous(umem_len)?;
        let registration = XdpUmemReg {
            addr: umem.address as u64,
            len: umem.len as u64,
            chunk_size: config.frame_size,
            headroom: config.frame_headroom,
            flags: 0,
            tx_metadata_len: 0,
        };
        set_socket_option(socket.as_raw_fd(), XDP_UMEM_REG, &registration)?;
        for option in [
            XDP_RX_RING,
            XDP_TX_RING,
            XDP_UMEM_FILL_RING,
            XDP_UMEM_COMPLETION_RING,
        ] {
            set_socket_option(socket.as_raw_fd(), option, &config.frame_count)?;
        }

        // SAFETY: this is a plain C-layout output buffer whose length is
        // initialized to its exact size.
        let mut offsets: XdpMmapOffsets = unsafe { zeroed() };
        let mut offsets_len = size_of::<XdpMmapOffsets>() as u32;
        // SAFETY: pointers and length refer to `offsets` for the whole call.
        let result = unsafe {
            getsockopt(
                socket.as_raw_fd(),
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                (&mut offsets as *mut XdpMmapOffsets).cast(),
                &mut offsets_len,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if offsets_len < size_of::<XdpMmapOffsets>() as u32 {
            return Err(AfXdpError::InvalidConfig(format!(
                "kernel returned only {offsets_len} bytes of AF_XDP ring offsets"
            )));
        }

        let rx = Ring::map(
            socket.as_raw_fd(),
            offsets.rx,
            config.frame_count,
            XDP_PGOFF_RX_RING,
        )?;
        let tx = Ring::map(
            socket.as_raw_fd(),
            offsets.tx,
            config.frame_count,
            XDP_PGOFF_TX_RING,
        )?;
        let fill = Ring::map(
            socket.as_raw_fd(),
            offsets.fill,
            config.frame_count,
            XDP_UMEM_PGOFF_FILL_RING,
        )?;
        let completion = Ring::map(
            socket.as_raw_fd(),
            offsets.completion,
            config.frame_count,
            XDP_UMEM_PGOFF_COMPLETION_RING,
        )?;

        let address = SockAddrXdp {
            family: AF_XDP as u16,
            flags: XDP_COPY | XDP_USE_NEED_WAKEUP,
            ifindex: config.ifindex,
            queue_id: config.queue_id,
            shared_umem_fd: 0,
        };
        // SAFETY: `address` has the exact sockaddr_xdp C layout and remains
        // live for the call.
        let result = unsafe {
            bind(
                socket.as_raw_fd(),
                (&address as *const SockAddrXdp).cast(),
                size_of::<SockAddrXdp>() as u32,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }

        let mut provider = Self {
            config,
            socket,
            umem,
            rx,
            tx,
            fill,
            completion,
            pending_fill: (0..config.frame_count)
                .map(|index| index as u64 * config.frame_size as u64)
                .collect(),
            in_flight: BTreeMap::new(),
            next_cookie: 1,
            xskmap_slots: BTreeSet::new(),
        };
        provider.flush_fill();
        provider.wake_rx()?;
        Ok(provider)
    }

    /// Declare that this socket owns one virtual XSKMAP slot for redirect
    /// completion. The map itself still stores only deterministic scalar data.
    pub fn bind_xskmap_slot(&mut self, map_index: u32, key: u32) -> bool {
        self.xskmap_slots.insert((map_index, key))
    }

    pub fn unbind_xskmap_slot(&mut self, map_index: u32, key: u32) -> bool {
        self.xskmap_slots.remove(&(map_index, key))
    }

    pub fn config(&self) -> AfXdpConfig {
        self.config
    }

    fn normalize_address(&self, address: u64) -> Option<u64> {
        let mask = !(self.config.frame_size as u64 - 1);
        let base = address & mask;
        (base < self.umem.len as u64).then_some(base)
    }

    fn invalid_descriptor(&mut self, descriptor: XdpDesc) -> AfXdpError {
        if let Some(base) = self.normalize_address(descriptor.addr) {
            self.pending_fill.push_back(base);
            self.flush_fill();
        }
        AfXdpError::InvalidDescriptor {
            addr: descriptor.addr,
            len: descriptor.len,
        }
    }

    fn flush_fill(&mut self) {
        while let Some(&address) = self.pending_fill.front() {
            if !self.fill.push(address) {
                break;
            }
            self.pending_fill.pop_front();
        }
    }

    fn reap_completions(&mut self) {
        while let Some(address) = self.completion.pop() {
            if let Some(base) = self.normalize_address(address) {
                self.pending_fill.push_back(base);
            }
        }
        self.flush_fill();
    }

    fn allocate_cookie(&mut self, base: u64) -> u64 {
        loop {
            let cookie = self.next_cookie;
            self.next_cookie = self.next_cookie.wrapping_add(1).max(1);
            if let alloc::collections::btree_map::Entry::Vacant(entry) =
                self.in_flight.entry(cookie)
            {
                entry.insert(base);
                return cookie;
            }
        }
    }

    fn wake_rx(&self) -> Result<(), AfXdpError> {
        if !self.fill.needs_wakeup() {
            return Ok(());
        }
        let mut descriptor = PollFd {
            fd: self.socket.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor is a live one-element pollfd array. A zero
        // timeout preserves the provider's nonblocking receive contract.
        let result = unsafe { poll(&mut descriptor, 1, 0) };
        if result < 0 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }

    fn kick_tx(&self) -> Result<(), AfXdpError> {
        if !self.tx.needs_wakeup() {
            return Ok(());
        }
        // SAFETY: a zero-length sendto with no destination is the documented
        // AF_XDP TX wakeup operation.
        let result = unsafe { sendto(self.socket.as_raw_fd(), null(), 0, MSG_DONTWAIT, null(), 0) };
        if result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock
            || matches!(error.raw_os_error(), Some(16 | 105))
        {
            Ok(())
        } else {
            Err(error.into())
        }
    }

    fn transmit(&mut self, frame: XdpFrame, base: u64) -> Result<(), AfXdpError> {
        self.reap_completions();
        let (storage, start, end) = frame.into_storage();
        if self.normalize_address(base) != Some(base)
            || end > self.config.frame_size as usize
            || start > end
        {
            self.pending_fill.push_back(base);
            self.flush_fill();
            return Err(AfXdpError::InvalidDescriptor {
                addr: base.saturating_add(start as u64),
                len: end.saturating_sub(start) as u32,
            });
        }
        // SAFETY: validation above proves the destination is within UMEM, and
        // `storage[start..end]` is a live source slice. The regions cannot
        // overlap because frame execution owns a separate allocation.
        unsafe {
            copy_nonoverlapping(
                storage.as_ptr().add(start),
                self.umem.address.add(base as usize + start),
                end - start,
            );
        }
        let descriptor = XdpDesc {
            addr: base + start as u64,
            len: (end - start) as u32,
            options: 0,
        };
        if !self.tx.push(descriptor) {
            self.pending_fill.push_back(base);
            self.flush_fill();
            return Err(AfXdpError::TxRingFull);
        }
        self.kick_tx()
    }

    fn should_transmit(
        &self,
        action: Option<XdpAction>,
        redirect: Option<XdpRedirect>,
    ) -> Result<bool, AfXdpError> {
        completion_transmits(
            self.config.pass,
            self.config.ifindex,
            &self.xskmap_slots,
            action,
            redirect,
        )
    }

    fn recycle(&mut self, base: u64) {
        self.pending_fill.push_back(base);
        self.flush_fill();
    }
}

fn completion_transmits(
    pass: PassDisposition,
    ifindex: u32,
    xskmap_slots: &BTreeSet<(u32, u32)>,
    action: Option<XdpAction>,
    redirect: Option<XdpRedirect>,
) -> Result<bool, AfXdpError> {
    match action {
        Some(XdpAction::Tx) => Ok(true),
        Some(XdpAction::Pass) => Ok(pass == PassDisposition::Transmit),
        Some(XdpAction::Redirect) => match redirect {
            Some(XdpRedirect::Interface {
                ifindex: destination,
                ..
            }) if destination == ifindex => Ok(true),
            Some(XdpRedirect::Map {
                map_index,
                map_kind: crate::maps::MapKind::XskMap,
                key,
                ..
            }) if xskmap_slots.contains(&(map_index, key)) => Ok(true),
            Some(destination) => Err(AfXdpError::UnboundRedirect(destination)),
            None => Err(AfXdpError::InvalidConfig(
                "XDP_REDIRECT completed without a destination".into(),
            )),
        },
        _ => Ok(false),
    }
}

impl XdpProvider for AfXdpProvider {
    type Error = AfXdpError;

    fn receive(&mut self) -> Result<Option<XdpFrame>, Self::Error> {
        self.reap_completions();
        self.wake_rx()?;
        let Some(descriptor) = self.rx.pop() else {
            return Ok(None);
        };
        if descriptor.options != 0 {
            return Err(self.invalid_descriptor(descriptor));
        }
        let Some(base) = self.normalize_address(descriptor.addr) else {
            return Err(self.invalid_descriptor(descriptor));
        };
        let start = (descriptor.addr - base) as usize;
        let Some(end) = start.checked_add(descriptor.len as usize) else {
            return Err(self.invalid_descriptor(descriptor));
        };
        if end > self.config.frame_size as usize {
            return Err(self.invalid_descriptor(descriptor));
        }
        if self.in_flight.values().any(|owned| *owned == base) {
            return Err(AfXdpError::InvalidDescriptor {
                addr: descriptor.addr,
                len: descriptor.len,
            });
        }
        let mut storage = vec![0; self.config.frame_size as usize];
        // SAFETY: descriptor validation proves the source range lies inside
        // UMEM; the destination is the equally sized owned frame allocation.
        unsafe {
            copy_nonoverlapping(
                self.umem.address.add(base as usize),
                storage.as_mut_ptr(),
                storage.len(),
            );
        }
        let mut frame =
            XdpFrame::from_storage(storage, start, end).map_err(AfXdpError::InvalidConfig)?;
        frame.set_cookie(self.allocate_cookie(base));
        frame.set_metadata(XdpMetadata {
            ingress_ifindex: self.config.ifindex,
            rx_queue_index: self.config.queue_id,
            egress_ifindex: 0,
        });
        frame.set_capabilities(XdpCapabilities {
            adjust_head: true,
            adjust_tail: true,
        });
        Ok(Some(frame))
    }

    fn complete(&mut self, completed: CompletedXdpFrame) -> Result<(), Self::Error> {
        let CompletedXdpFrame { frame, result } = completed;
        let Some(base) = self.in_flight.remove(&frame.cookie()) else {
            return Err(AfXdpError::ForeignFrame(frame.cookie()));
        };
        let route = match &result {
            Ok(verdict) => self.should_transmit(verdict.action, verdict.redirect),
            Err(_) => Ok(false),
        };
        match route {
            Ok(true) => self.transmit(frame, base),
            Ok(false) => {
                self.recycle(base);
                Ok(())
            }
            Err(error) => {
                self.recycle(base);
                Err(error)
            }
        }
    }
}

fn set_socket_option<T>(fd: c_int, option: c_int, value: &T) -> Result<(), AfXdpError> {
    // SAFETY: `value` points to a live plain C-compatible scalar/struct for
    // the exact duration and byte length passed to the kernel.
    let result = unsafe {
        setsockopt(
            fd,
            SOL_XDP,
            option,
            (value as *const T).cast(),
            size_of::<T>() as u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_rejects_invalid_umem_geometry() {
        let mut config = AfXdpConfig::new(1, 0);
        config.frame_count = 3;
        assert!(matches!(
            config.validate(),
            Err(AfXdpError::InvalidConfig(_))
        ));
        config.frame_count = 4;
        config.frame_size = 1024;
        assert!(matches!(
            config.validate(),
            Err(AfXdpError::InvalidConfig(_))
        ));
        config.frame_size = 2048;
        config.frame_headroom = 2048;
        assert!(matches!(
            config.validate(),
            Err(AfXdpError::InvalidConfig(_))
        ));
    }

    #[test]
    fn loopback_interface_can_be_resolved() {
        assert_ne!(interface_index("lo").unwrap(), 0);
        assert!(interface_index("").is_err());
        assert!(interface_index("bad\0name").is_err());
    }

    #[test]
    fn completion_routes_only_to_explicitly_owned_destinations() {
        let mut slots = BTreeSet::new();
        slots.insert((3, 7));
        let owned = XdpRedirect::Map {
            map_index: 3,
            map_kind: crate::maps::MapKind::XskMap,
            key: 7,
            flags: 0,
        };
        assert!(completion_transmits(
            PassDisposition::Recycle,
            9,
            &slots,
            Some(XdpAction::Redirect),
            Some(owned),
        )
        .unwrap());
        let unowned = XdpRedirect::Map {
            map_index: 3,
            map_kind: crate::maps::MapKind::XskMap,
            key: 8,
            flags: 0,
        };
        assert!(matches!(
            completion_transmits(
                PassDisposition::Recycle,
                9,
                &slots,
                Some(XdpAction::Redirect),
                Some(unowned),
            ),
            Err(AfXdpError::UnboundRedirect(_))
        ));
        assert!(!completion_transmits(
            PassDisposition::Recycle,
            9,
            &slots,
            Some(XdpAction::Pass),
            None,
        )
        .unwrap());
        assert!(completion_transmits(
            PassDisposition::Transmit,
            9,
            &slots,
            Some(XdpAction::Pass),
            None,
        )
        .unwrap());
        assert!(completion_transmits(
            PassDisposition::Recycle,
            9,
            &slots,
            Some(XdpAction::Redirect),
            Some(XdpRedirect::Interface {
                ifindex: 9,
                flags: 0,
            }),
        )
        .unwrap());
        assert!(matches!(
            completion_transmits(
                PassDisposition::Recycle,
                9,
                &slots,
                Some(XdpAction::Redirect),
                Some(XdpRedirect::Interface {
                    ifindex: 10,
                    flags: 0,
                }),
            ),
            Err(AfXdpError::UnboundRedirect(_))
        ));
    }

    #[test]
    fn uapi_layouts_match_linux_if_xdp() {
        assert_eq!(size_of::<XdpRingOffset>(), 32);
        assert_eq!(size_of::<XdpMmapOffsets>(), 128);
        assert_eq!(size_of::<XdpUmemReg>(), 32);
        assert_eq!(size_of::<SockAddrXdp>(), 16);
        assert_eq!(size_of::<XdpDesc>(), 16);
    }

    #[test]
    fn ring_ownership_wraps_without_overwriting_live_entries() {
        let mapping = Mapping::anonymous(128).unwrap();
        let base = mapping.address;
        let mut ring = Ring::<u64> {
            // SAFETY: this test-owned mapping is zero-initialized and the
            // selected offsets are aligned, disjoint, and within its bounds.
            producer: base.cast(),
            // SAFETY: see `producer`.
            consumer: unsafe { base.add(4).cast() },
            // SAFETY: see `producer`.
            flags: unsafe { base.add(8).cast() },
            // SAFETY: see `producer`.
            entries: unsafe { base.add(16).cast() },
            _mapping: mapping,
            count: 4,
            mask: 3,
        };
        for value in 1..=4 {
            assert!(ring.push(value));
        }
        assert!(!ring.push(99));
        assert_eq!(ring.pop(), Some(1));
        assert_eq!(ring.pop(), Some(2));
        assert!(ring.push(5));
        assert!(ring.push(6));
        assert_eq!(
            (0..4).map(|_| ring.pop().unwrap()).collect::<Vec<_>>(),
            vec![3, 4, 5, 6]
        );
        assert_eq!(ring.pop(), None);
    }

    #[test]
    #[ignore = "requires a configured Linux AF_XDP interface/queue and privileges"]
    fn opens_live_socket_from_environment() {
        let name = std::env::var("FEBPF_AF_XDP_IFACE").unwrap();
        let queue = std::env::var("FEBPF_AF_XDP_QUEUE")
            .unwrap_or_else(|_| "0".into())
            .parse()
            .unwrap();
        let provider =
            AfXdpProvider::open(AfXdpConfig::new(interface_index(&name).unwrap(), queue)).unwrap();
        assert_eq!(provider.config().queue_id, queue);
    }
}
