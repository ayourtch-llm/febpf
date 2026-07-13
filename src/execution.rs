//! Composable per-invocation resources.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::packet::{XdpCapabilities, XdpFrame, XdpRedirect};

/// Context ABI selected when a program is verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextModel {
    Flat,
    Btf,
    Xdp,
    Skb,
    Metadata(crate::interp::MetadataLayout),
}

enum ContextStorage<'a> {
    Borrowed(&'a mut [u8]),
    Owned(Vec<u8>),
}

impl ContextStorage<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

struct PacketWindow<'a> {
    storage: &'a mut [u8],
    data_start: usize,
    data_end: usize,
    capabilities: XdpCapabilities,
    bounds_target: Option<(&'a mut usize, &'a mut usize)>,
}

impl PacketWindow<'_> {
    fn len(&self) -> usize {
        self.data_end - self.data_start
    }

    fn active(&self) -> &[u8] {
        &self.storage[self.data_start..self.data_end]
    }

    fn active_mut(&mut self) -> &mut [u8] {
        &mut self.storage[self.data_start..self.data_end]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketSource {
    None,
    Context,
    Window,
    Owned(u32),
}

/// Resources and completion state for one VM invocation.
pub struct ExecutionEnvironment<'a> {
    context: ContextStorage<'a>,
    model: ContextModel,
    packet: Option<PacketWindow<'a>>,
    kernel_memory: Vec<u8>,
    printk: Option<PrintkSink<'a>>,
    seq_output: Option<&'a mut Vec<u8>>,
    pub(crate) packet_source: PacketSource,
    pub(crate) redirect: Option<XdpRedirect>,
}

struct PrintkSink<'a> {
    output: &'a mut Vec<String>,
    echo: bool,
}

/// Provider-neutral result of one execution environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub return_value: u64,
    pub redirect: Option<XdpRedirect>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EnvironmentSnapshot {
    context: Vec<u8>,
    model: ContextModel,
    packet_storage: Option<Vec<u8>>,
    packet_start: usize,
    packet_end: usize,
    packet_capabilities: XdpCapabilities,
    packet_source: PacketSource,
    printk: Option<Vec<String>>,
    printk_echo: bool,
    seq_output: Option<Vec<u8>>,
    redirect: Option<XdpRedirect>,
}

impl<'a> ExecutionEnvironment<'a> {
    pub fn plain(context: &'a mut [u8]) -> Self {
        Self {
            context: ContextStorage::Borrowed(context),
            model: ContextModel::Flat,
            packet: None,
            kernel_memory: Vec::new(),
            printk: None,
            seq_output: None,
            packet_source: PacketSource::None,
            redirect: None,
        }
    }

    pub fn raw_packet(context: &'a mut [u8]) -> Self {
        let mut env = Self::plain(context);
        env.packet_source = PacketSource::Context;
        env
    }

    /// Build an invocation around caller-owned context bytes and a verified
    /// context ABI. Execution still rejects a model different from the VM's.
    pub fn for_context(context: &'a mut [u8], model: ContextModel) -> Self {
        Self::borrowed(context, model, PacketSource::None)
    }

    pub(crate) fn borrowed(
        context: &'a mut [u8],
        model: ContextModel,
        packet_source: PacketSource,
    ) -> Self {
        Self {
            context: ContextStorage::Borrowed(context),
            model,
            packet: None,
            kernel_memory: Vec::new(),
            printk: None,
            seq_output: None,
            packet_source,
            redirect: None,
        }
    }

    pub fn xdp(frame: &'a mut XdpFrame) -> Result<Self, String> {
        if frame.capacity() > u32::MAX as usize {
            return Err("XDP frame storage is too large for virtual packet offsets".into());
        }
        let metadata = frame.metadata();
        let mut context = vec![0u8; 24];
        context[12..16].copy_from_slice(&metadata.ingress_ifindex.to_le_bytes());
        context[16..20].copy_from_slice(&metadata.rx_queue_index.to_le_bytes());
        context[20..24].copy_from_slice(&metadata.egress_ifindex.to_le_bytes());
        let (storage, data_start, data_end, capabilities) = frame.execution_parts();
        let start = *data_start;
        let end = *data_end;
        Ok(Self {
            context: ContextStorage::Owned(context),
            model: ContextModel::Xdp,
            packet: Some(PacketWindow {
                storage,
                data_start: start,
                data_end: end,
                capabilities,
                bounds_target: Some((data_start, data_end)),
            }),
            kernel_memory: Vec::new(),
            printk: None,
            seq_output: None,
            packet_source: PacketSource::Window,
            redirect: None,
        })
    }

    pub fn xdp_slice(packet: &'a mut [u8]) -> Result<Self, String> {
        if packet.len() > u32::MAX as usize {
            return Err("packet is too large for XDP virtual packet offsets".into());
        }
        let end = packet.len();
        Ok(Self {
            context: ContextStorage::Owned(vec![0u8; 24]),
            model: ContextModel::Xdp,
            packet: Some(PacketWindow {
                storage: packet,
                data_start: 0,
                data_end: end,
                capabilities: XdpCapabilities::default(),
                bounds_target: None,
            }),
            kernel_memory: Vec::new(),
            printk: None,
            seq_output: None,
            packet_source: PacketSource::Window,
            redirect: None,
        })
    }

    pub fn skb(packet: &'a mut [u8]) -> Result<Self, String> {
        if packet.len() > u32::MAX as usize {
            return Err("packet is too large for __sk_buff.len".into());
        }
        let mut context = vec![0u8; 192];
        context[0..4].copy_from_slice(&(packet.len() as u32).to_le_bytes());
        if packet.len() >= 14 {
            let protocol = u16::from_le_bytes([packet[12], packet[13]]) as u32;
            context[16..20].copy_from_slice(&protocol.to_le_bytes());
        }
        let end = packet.len();
        Ok(Self {
            context: ContextStorage::Owned(context),
            model: ContextModel::Skb,
            packet: Some(PacketWindow {
                storage: packet,
                data_start: 0,
                data_end: end,
                capabilities: XdpCapabilities::default(),
                bounds_target: None,
            }),
            kernel_memory: Vec::new(),
            printk: None,
            seq_output: None,
            packet_source: PacketSource::Window,
            redirect: None,
        })
    }

    pub(crate) fn owned_packet(context: &'a mut [u8], model: ContextModel, index: u32) -> Self {
        Self {
            context: ContextStorage::Borrowed(context),
            model,
            packet: None,
            kernel_memory: Vec::new(),
            printk: None,
            seq_output: None,
            packet_source: PacketSource::Owned(index),
            redirect: None,
        }
    }

    pub fn model(&self) -> ContextModel {
        self.model
    }

    pub fn context(&self) -> &[u8] {
        self.context.as_slice()
    }

    pub fn context_mut(&mut self) -> &mut [u8] {
        self.context.as_mut_slice()
    }

    pub fn redirect(&self) -> Option<XdpRedirect> {
        self.redirect
    }

    /// Install a caller-owned iterator output sink. This add-on composes with
    /// any compatible context and packet adapter.
    pub fn with_seq_output(mut self, output: &'a mut Vec<u8>) -> Self {
        self.seq_output = Some(output);
        self
    }

    /// Install a caller-owned trace output sink.
    pub fn with_printk(mut self, output: &'a mut Vec<String>, echo: bool) -> Self {
        self.printk = Some(PrintkSink { output, echo });
        self
    }

    pub(crate) fn printk_mut(&mut self) -> Option<(&mut Vec<String>, bool)> {
        let sink = self.printk.as_mut()?;
        Some((sink.output, sink.echo))
    }

    pub(crate) fn set_echo_printk(&mut self, echo: bool) -> Option<bool> {
        let sink = self.printk.as_mut()?;
        Some(core::mem::replace(&mut sink.echo, echo))
    }

    pub(crate) fn seq_output_mut(&mut self) -> Option<&mut Vec<u8>> {
        self.seq_output.as_deref_mut()
    }

    pub(crate) fn packet_len(&self) -> usize {
        self.packet.as_ref().map_or(0, PacketWindow::len)
    }

    pub(crate) fn has_packet_window(&self) -> bool {
        self.packet.is_some()
    }

    pub(crate) fn packet(&self) -> &[u8] {
        self.packet.as_ref().map_or(&[], PacketWindow::active)
    }

    pub(crate) fn packet_mut(&mut self) -> &mut [u8] {
        match &mut self.packet {
            Some(packet) => packet.active_mut(),
            None => &mut [],
        }
    }

    pub(crate) fn adjust_head(&mut self, delta: i32) -> Result<(), i32> {
        let packet = self.packet.as_mut().ok_or(-14)?; // -EFAULT
        if !packet.capabilities.adjust_head {
            return Err(-95); // -EOPNOTSUPP
        }
        if delta >= 0 {
            let amount = delta as usize;
            if amount > packet.len() {
                return Err(-22); // -EINVAL
            }
            packet.data_start += amount;
        } else {
            let amount = delta.unsigned_abs() as usize;
            if amount > packet.data_start {
                return Err(-22);
            }
            packet.data_start -= amount;
        }
        Ok(())
    }

    pub(crate) fn adjust_tail(&mut self, delta: i32) -> Result<(), i32> {
        let packet = self.packet.as_mut().ok_or(-14)?; // -EFAULT
        if !packet.capabilities.adjust_tail {
            return Err(-95); // -EOPNOTSUPP
        }
        if delta >= 0 {
            let amount = delta as usize;
            let new_end = packet.data_end.checked_add(amount).ok_or(-22)?;
            if new_end > packet.storage.len() {
                return Err(-22); // -EINVAL
            }
            packet.storage[packet.data_end..new_end].fill(0);
            packet.data_end = new_end;
        } else {
            let amount = delta.unsigned_abs() as usize;
            if amount > packet.len() {
                return Err(-22);
            }
            packet.data_end -= amount;
        }
        Ok(())
    }

    pub(crate) fn memory_parts(&mut self) -> (&mut [u8], &mut [u8], &mut Vec<u8>) {
        let context = self.context.as_mut_slice();
        let packet: &mut [u8] = match &mut self.packet {
            Some(packet) => packet.active_mut(),
            None => &mut [],
        };
        (context, packet, &mut self.kernel_memory)
    }

    pub(crate) fn snapshot(&self) -> EnvironmentSnapshot {
        let (packet_storage, packet_start, packet_end, packet_capabilities) = self
            .packet
            .as_ref()
            .map_or((None, 0, 0, XdpCapabilities::default()), |packet| {
                (
                    Some(packet.storage.to_vec()),
                    packet.data_start,
                    packet.data_end,
                    packet.capabilities,
                )
            });
        EnvironmentSnapshot {
            context: self.context().to_vec(),
            model: self.model,
            packet_storage,
            packet_start,
            packet_end,
            packet_capabilities,
            packet_source: self.packet_source,
            printk: self.printk.as_ref().map(|sink| sink.output.clone()),
            printk_echo: self.printk.as_ref().is_some_and(|sink| sink.echo),
            seq_output: self.seq_output.as_deref().cloned(),
            redirect: self.redirect,
        }
    }

    pub(crate) fn restore(&mut self, snapshot: &EnvironmentSnapshot) {
        assert_eq!(
            self.model, snapshot.model,
            "snapshot context model mismatch"
        );
        assert_eq!(
            self.packet_source, snapshot.packet_source,
            "snapshot packet source mismatch"
        );
        self.context_mut().copy_from_slice(&snapshot.context);
        match (&mut self.packet, &snapshot.packet_storage) {
            (Some(packet), Some(storage)) => {
                packet.storage.copy_from_slice(storage);
                packet.data_start = snapshot.packet_start;
                packet.data_end = snapshot.packet_end;
                packet.capabilities = snapshot.packet_capabilities;
            }
            (None, None) => {}
            _ => panic!("snapshot packet topology mismatch"),
        }
        match (&mut self.seq_output, &snapshot.seq_output) {
            (Some(output), Some(saved)) => output.clone_from(saved),
            (None, None) => {}
            _ => panic!("snapshot output topology mismatch"),
        }
        match (&mut self.printk, &snapshot.printk) {
            (Some(sink), Some(saved)) => {
                sink.output.clone_from(saved);
                sink.echo = snapshot.printk_echo;
            }
            (None, None) => {}
            _ => panic!("snapshot printk topology mismatch"),
        }
        self.redirect = snapshot.redirect;
    }
}

impl Drop for ExecutionEnvironment<'_> {
    fn drop(&mut self) {
        if let Some(packet) = &mut self.packet {
            if let Some((start, end)) = &mut packet.bounds_target {
                **start = packet.data_start;
                **end = packet.data_end;
            }
        }
    }
}
