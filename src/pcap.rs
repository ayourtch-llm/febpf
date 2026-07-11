//! Minimal zero-dependency reader for classic libpcap capture files.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampResolution {
    Microseconds,
    Nanoseconds,
}

#[derive(Debug, Clone, Copy)]
pub struct Packet<'a> {
    pub timestamp_secs: u32,
    pub timestamp_fraction: u32,
    pub original_len: u32,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub struct Capture<'a> {
    pub resolution: TimestampResolution,
    pub snaplen: u32,
    pub link_type: u32,
    pub packets: Vec<Packet<'a>>,
}

pub fn parse(bytes: &[u8]) -> Result<Capture<'_>, String> {
    let magic = bytes.get(..4).ok_or("pcap: truncated global header")?;
    let (le, resolution) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, TimestampResolution::Microseconds),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, TimestampResolution::Microseconds),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, TimestampResolution::Nanoseconds),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, TimestampResolution::Nanoseconds),
        _ => return Err("pcap: bad magic (pcapng is not supported)".into()),
    };
    let u16_at = |off: usize| -> Result<u16, String> {
        let b: [u8; 2] = bytes
            .get(off..off + 2)
            .ok_or("pcap: truncated global header")?
            .try_into()
            .unwrap();
        Ok(if le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) })
    };
    let u32_at = |off: usize| -> Result<u32, String> {
        let b: [u8; 4] = bytes
            .get(off..off + 4)
            .ok_or("pcap: truncated data")?
            .try_into()
            .unwrap();
        Ok(if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
    };
    let (major, minor) = (u16_at(4)?, u16_at(6)?);
    if (major, minor) != (2, 4) {
        return Err(format!("pcap: unsupported version {major}.{minor} (expected 2.4)"));
    }
    let snaplen = u32_at(16)?;
    let link_type = u32_at(20)?;
    let mut packets = Vec::new();
    let mut off = 24usize;
    while off < bytes.len() {
        if bytes.len() - off < 16 {
            return Err(format!("pcap: truncated packet header at byte {off}"));
        }
        let timestamp_secs = u32_at(off)?;
        let timestamp_fraction = u32_at(off + 4)?;
        let captured_len = u32_at(off + 8)?;
        let original_len = u32_at(off + 12)?;
        if captured_len > snaplen {
            return Err(format!(
                "pcap: packet {} captured length {captured_len} exceeds snaplen {snaplen}",
                packets.len()
            ));
        }
        let start = off + 16;
        let end = start
            .checked_add(captured_len as usize)
            .ok_or("pcap: packet length overflow")?;
        let data = bytes.get(start..end).ok_or_else(|| {
            format!(
                "pcap: packet {} truncated (needs {captured_len} bytes)",
                packets.len()
            )
        })?;
        packets.push(Packet {
            timestamp_secs,
            timestamp_fraction,
            original_len,
            data,
        });
        off = end;
    }
    Ok(Capture {
        resolution,
        snaplen,
        link_type,
        packets,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse, TimestampResolution};

    fn le_capture() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&4u16.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&64u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        for (sec, data) in [(10u32, &[1u8, 2, 3][..]), (11, &[4, 5][..])] {
            b.extend_from_slice(&sec.to_le_bytes());
            b.extend_from_slice(&7u32.to_le_bytes());
            b.extend_from_slice(&(data.len() as u32).to_le_bytes());
            b.extend_from_slice(&(data.len() as u32).to_le_bytes());
            b.extend_from_slice(data);
        }
        b
    }

    #[test]
    fn reads_classic_pcap_records() {
        let b = le_capture();
        let c = parse(&b).unwrap();
        assert_eq!(c.resolution, TimestampResolution::Microseconds);
        assert_eq!((c.snaplen, c.link_type), (64, 1));
        assert_eq!(c.packets.len(), 2);
        assert_eq!(c.packets[0].data, [1, 2, 3]);
        assert_eq!(c.packets[1].timestamp_secs, 11);
    }

    #[test]
    fn rejects_truncation_and_pcapng() {
        let mut b = le_capture();
        b.pop();
        assert!(parse(&b).unwrap_err().contains("truncated"));
        assert!(parse(&[0x0a, 0x0d, 0x0d, 0x0a]).unwrap_err().contains("pcapng"));
    }
}
