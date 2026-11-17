//! Janome machines that work with the dotCustomizer app (the IJ521 and
//! its relatives), spoken to over Wi-Fi.
//!
//! The protocol was reverse-engineered from dotCustomizer: everything
//! happens on port 50521. Machines answer a UDP broadcast asking them
//! to reply (command 1) with a 44-byte packet naming themselves, answer
//! a status query (command 2) over UDP or TCP with a 48-byte packet,
//! and take a JEF upload over TCP: a length notice (command 12) and
//! then the file itself (command 13), padded with zeros to a multiple
//! of four bytes. Every packet is a plain 20-byte header — the magic
//! `janome:\0` from the app, `JANOME:\0` from the machine, then the
//! command and three parameters, all little-endian — plus a payload.
//! There is no pairing and no encryption.
//!
//! Verified against a mock that answers exactly as the analysis says a
//! machine does; not yet against a real machine.

use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// The port the app and the machines talk on.
pub const PORT: u16 = 50521;

/// The IJ521's sewing field, mm (its profile's hoop).
pub const IJ521_FIELD_MM: f64 = 102.0;

const CMD_MUST_REPLY: u16 = 1;
const CMD_MACHINE_STATUS: u16 = 2;
const CMD_NOTIFY_JEF_LENGTH: u16 = 12;
const CMD_SEND_JEF_DATA: u16 = 13;

/// One packet: the 20-byte header plus its payload.
pub fn datagram(cmd: u16, param_a: u16, param_b: u32, param_c: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + payload.len());
    out.extend_from_slice(b"janome:\x00");
    out.extend_from_slice(&cmd.to_le_bytes());
    out.extend_from_slice(&param_a.to_le_bytes());
    out.extend_from_slice(&param_b.to_le_bytes());
    out.extend_from_slice(&param_c.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// A parsed packet: (command, param_a, param_b, param_c, payload).
pub type Datagram<'a> = (u16, u16, u32, u32, &'a [u8]);

/// Parse a packet from the machine (or the app). The magic is not
/// checked beyond its length: the app sends `janome:` and the machine
/// answers `JANOME:`.
pub fn parse_datagram(data: &[u8]) -> Option<Datagram<'_>> {
    if data.len() < 20 {
        return None;
    }
    let u16le = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]);
    let u32le = |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
    Some((u16le(8), u16le(10), u32le(12), u32le(16), &data[20..]))
}

/// A machine that answered discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    pub ip: String,
    /// The model number the machine reports (the IJ521 reports 52103).
    pub model: u32,
    pub name: String,
}

/// Parse a 44-byte discovery reply.
pub fn parse_discovery(data: &[u8], ip: IpAddr) -> Option<Machine> {
    if data.len() != 44 || !data.starts_with(b"JANOME:") {
        return None;
    }
    let (_, _, model, _, payload) = parse_datagram(data)?;
    let name_bytes = &payload[..payload.len().min(24)];
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
    let name: String = name_bytes[..end].iter().map(|&b| char::from(b)).collect();
    let name = name.trim().to_string();
    Some(Machine {
        ip: ip.to_string(),
        model,
        name: if name.is_empty() { "Janome machine".to_string() } else { name },
    })
}

/// Where discovery broadcasts go: the limited broadcast, plus the
/// subnet broadcast of the address the default route uses (home
/// routers sometimes drop the limited one).
fn broadcast_targets() -> Vec<Ipv4Addr> {
    let mut targets = vec![Ipv4Addr::BROADCAST];
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        // Connecting a UDP socket sends nothing; it just picks a route.
        if sock.connect("192.168.0.1:9").is_ok() {
            if let Ok(SocketAddr::V4(addr)) = sock.local_addr() {
                let o = addr.ip().octets();
                targets.push(Ipv4Addr::new(o[0], o[1], o[2], 255));
            }
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

/// Ask every Janome machine on the local network to identify itself.
pub fn discover(timeout: Duration) -> Result<Vec<Machine>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;
    let pkt = datagram(CMD_MUST_REPLY, 0, 0, 44, &[]);
    for target in broadcast_targets() {
        let _ = sock.send_to(&pkt, (target, PORT));
    }
    let deadline = Instant::now() + timeout;
    let mut found: BTreeMap<String, Machine> = BTreeMap::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                if let Some(m) = parse_discovery(&buf[..n], addr.ip()) {
                    found.insert(m.ip.clone(), m);
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(found.into_values().collect())
}

/// The machine's status, from its 48-byte status packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The raw status code (see [`Status::name`]).
    pub code: u8,
    /// How far through the loaded design the machine is, in stitches.
    pub stitch_position: u32,
    /// Needle position, in the machine's own units (0.1 mm).
    pub x: i16,
    pub y: i16,
    /// A checksum of the loaded design.
    pub design_crc: u16,
}

impl Status {
    /// What the code means, in the app's terms.
    pub fn name(&self) -> &'static str {
        match self.code {
            0 => "no data",
            1 => "sewing",
            2 => "reserved",
            3 => "color change",
            4 => "paused",
            5 => "complete",
            6 => "thread break",
            7 => "upper shaft locked",
            8 => "area check",
            9 => "jogging",
            10 => "hoop moving",
            11 => "bobbin winding",
            12 => "jump",
            13 => "hoop retracted",
            14 => "fatal error",
            15 => "XY not initialized",
            16 => "bobbin winding unavailable",
            97 => "move queue",
            98 => "status query",
            99 => "not connected",
            _ => "unknown",
        }
    }
}

/// Parse a 48-byte status packet.
pub fn parse_status(data: &[u8]) -> Result<Status> {
    if data.len() != 48 || !data.starts_with(b"JANOME:") {
        bail!("unexpected status reply ({} bytes)", data.len());
    }
    let (_, _, _, _, p) = parse_datagram(data).unwrap();
    if p.len() < 28 {
        bail!("short status reply ({} payload bytes)", p.len());
    }
    let u16le = |i: usize| u16::from_le_bytes([p[i], p[i + 1]]);
    let i16le = |i: usize| i16::from_le_bytes([p[i], p[i + 1]]);
    Ok(Status {
        code: p[22],
        stitch_position: u32::from_le_bytes([p[12], p[13], p[14], p[15]]),
        x: i16le(18),
        y: i16le(20),
        design_crc: u16le(6),
    })
}

/// Ask one machine for its status, over UDP.
pub fn status(host: &str, timeout: Duration) -> Result<Status> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(timeout))?;
    sock.send_to(&datagram(CMD_MACHINE_STATUS, 0, 0, 48, &[]), (host, PORT))?;
    let mut buf = [0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf)?;
    parse_status(&buf[..n])
}

fn read_exact(stream: &mut TcpStream, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Upload a JEF file to a machine over TCP, the way the app does:
/// a status exchange on connect, the length notice (command 12), then
/// the file (command 13). A reply whose first parameter is 0 means the
/// machine refused. Returns a short log of what happened.
pub fn send_jef(host: &str, jef: &[u8], timeout: Duration) -> Result<Vec<String>> {
    let mut padded = jef.to_vec();
    while padded.len() % 4 != 0 {
        padded.push(0);
    }
    let addr = (host, PORT)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve {host}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut log = Vec::new();

    // The app asks for status as soon as it connects. A failure here is
    // not fatal in the app, so it is not fatal here either.
    match status_on(&mut stream) {
        Ok(s) => log.push(format!("machine status: {} ({})", s.name(), s.code)),
        Err(e) => log.push(format!("status on connect unavailable ({e})")),
    }

    stream.write_all(&datagram(CMD_NOTIFY_JEF_LENGTH, 0, padded.len() as u32, 20, &[]))?;
    let reply = read_exact(&mut stream, 20)?;
    let (_, accepted, _, _, _) = parse_datagram(&reply).unwrap_or((0, 0, 0, 0, &[]));
    if accepted == 0 {
        bail!("the machine refused the upload (length notice)");
    }
    log.push(format!("length notice accepted ({} bytes)", padded.len()));

    stream.write_all(&datagram(CMD_SEND_JEF_DATA, 0, padded.len() as u32, 20, &padded))?;
    let reply = read_exact(&mut stream, 20)?;
    let (_, accepted, _, _, _) = parse_datagram(&reply).unwrap_or((0, 0, 0, 0, &[]));
    if accepted == 0 {
        bail!("the machine refused the upload (design data)");
    }
    log.push("design data accepted".to_string());
    Ok(log)
}

/// The status exchange the app runs on a fresh TCP connection.
fn status_on(stream: &mut TcpStream) -> Result<Status> {
    stream.write_all(&datagram(CMD_MACHINE_STATUS, 0, 0, 48, &[]))?;
    let reply = read_exact(stream, 48)?;
    parse_status(&reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine packet, the way the machine sends it.
    fn machine_packet(cmd: u16, a: u16, b: u32, c: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"JANOME:\x00");
        out.extend_from_slice(&cmd.to_le_bytes());
        out.extend_from_slice(&a.to_le_bytes());
        out.extend_from_slice(&b.to_le_bytes());
        out.extend_from_slice(&c.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn datagram_layout() {
        let d = datagram(CMD_SEND_JEF_DATA, 0, 1234, 20, &[9, 8, 7]);
        assert_eq!(&d[..8], b"janome:\x00");
        assert_eq!(d.len(), 23);
        let (cmd, a, b, c, payload) = parse_datagram(&d).unwrap();
        assert_eq!((cmd, a, b, c), (CMD_SEND_JEF_DATA, 0, 1234, 20));
        assert_eq!(payload, &[9, 8, 7]);
        assert!(parse_datagram(&d[..19]).is_none());
    }

    #[test]
    fn discovery_reply() {
        let mut name = b"MOCK-521\x00".to_vec();
        name.resize(24, 0);
        let pkt = machine_packet(CMD_MUST_REPLY, 1, 52103, 44, &name);
        let m = parse_discovery(&pkt, "192.168.1.50".parse().unwrap()).unwrap();
        assert_eq!(m.name, "MOCK-521");
        assert_eq!(m.model, 52103);
        assert_eq!(m.ip, "192.168.1.50");
        // Wrong length or the app's own magic is not a machine reply.
        assert!(parse_discovery(&pkt[..43], "192.168.1.50".parse().unwrap()).is_none());
        let mut app_pkt = pkt.clone();
        app_pkt[0] = b'j';
        assert!(parse_discovery(&app_pkt, "192.168.1.50".parse().unwrap()).is_none());
    }

    #[test]
    fn status_reply() {
        let mut p = [0u8; 28];
        p[6..8].copy_from_slice(&0x1234u16.to_le_bytes());
        p[12..16].copy_from_slice(&123u32.to_le_bytes());
        p[18..20].copy_from_slice(&10i16.to_le_bytes());
        p[20..22].copy_from_slice(&(-5i16).to_le_bytes());
        p[22] = 3;
        let pkt = machine_packet(CMD_MACHINE_STATUS, 1, 0, 48, &p);
        let s = parse_status(&pkt).unwrap();
        assert_eq!(s.code, 3);
        assert_eq!(s.name(), "color change");
        assert_eq!(s.stitch_position, 123);
        assert_eq!((s.x, s.y), (10, -5));
        assert_eq!(s.design_crc, 0x1234);
    }
}
