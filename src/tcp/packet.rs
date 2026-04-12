use internet_checksum::Checksum;
#[cfg(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "ios"
))]
use nix::libc::{AF_INET, AF_INET6};
use pnet::packet::Packet;
use pnet::packet::{ip, ipv4, ipv6, tcp};
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};
use zeroize::Zeroize;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
#[cfg(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "ios"
))]
pub const MAX_PACKET_LEN: usize = 1504;
#[cfg(not(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "ios"
)))]
pub const MAX_PACKET_LEN: usize = 1500;

pub enum IPPacket<'p> {
    V4(ipv4::Ipv4Packet<'p>),
    V6(ipv6::Ipv6Packet<'p>),
}

impl<'a> IPPacket<'a> {
    pub fn get_source(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.get_source()),
            IPPacket::V6(p) => IpAddr::V6(p.get_source()),
        }
    }

    pub fn get_destination(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.get_destination()),
            IPPacket::V6(p) => IpAddr::V6(p.get_destination()),
        }
    }
}

pub fn build_tcp_packet(
    buf: &mut [u8],
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u16,
    payload: Option<&[u8]>,
) -> Result<usize, String> {
    let ip_header_len = match local_addr {
        SocketAddr::V4(_) => IPV4_HEADER_LEN,
        SocketAddr::V6(_) => IPV6_HEADER_LEN,
    };
    let wscale = (flags & tcp::TcpFlags::SYN) != 0;
    let tcp_header_len = TCP_HEADER_LEN + if wscale { 4 } else { 0 }; // nop + wscale
    let tcp_total_len = tcp_header_len + payload.map_or(0, |payload| payload.len());
    let total_len = ip_header_len + tcp_total_len;
    #[cfg(not(any(
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios"
    )))]
    let offset = 0;
    #[cfg(any(
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios"
    ))]
    let offset = 4;

    if total_len + offset > buf.len() {
        return Err(format!(
            "Provided buffer does not have sufficent space: buffer size: {}, total length: {}",
            buf.len(),
            total_len + offset
        ));
    }

    buf[..total_len + offset].zeroize();

    match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            let mut v4 =
                ipv4::MutableIpv4Packet::new(&mut buf[offset..ip_header_len + offset]).unwrap();
            v4.set_version(4);
            v4.set_header_length(IPV4_HEADER_LEN as u8 / 4);
            v4.set_next_level_protocol(ip::IpNextHeaderProtocols::Tcp);
            v4.set_ttl(64);
            v4.set_source(*local.ip());
            v4.set_destination(*remote.ip());
            v4.set_total_length(total_len.try_into().unwrap());
            v4.set_flags(ipv4::Ipv4Flags::DontFragment);
            let mut cksm = Checksum::new();
            cksm.add_bytes(v4.packet());
            v4.set_checksum(u16::from_be_bytes(cksm.checksum()));

            #[cfg(any(
                target_os = "openbsd",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "dragonfly",
                target_os = "macos",
                target_os = "ios"
            ))]
            {
                buf[3] = AF_INET as u8;
            }
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            let mut v6 =
                ipv6::MutableIpv6Packet::new(&mut buf[offset..ip_header_len + offset]).unwrap();
            v6.set_version(6);
            v6.set_payload_length(tcp_total_len.try_into().unwrap());
            v6.set_next_header(ip::IpNextHeaderProtocols::Tcp);
            v6.set_hop_limit(64);
            v6.set_source(*local.ip());
            v6.set_destination(*remote.ip());

            #[cfg(any(
                target_os = "openbsd",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "dragonfly",
                target_os = "macos",
                target_os = "ios"
            ))]
            {
                buf[3] = AF_INET6 as u8;
            }
        }
        _ => unreachable!(),
    };

    let mut tcp =
        tcp::MutableTcpPacket::new(&mut buf[ip_header_len + offset..total_len + offset]).unwrap();
    tcp.set_window(0xffff);
    tcp.set_source(local_addr.port());
    tcp.set_destination(remote_addr.port());
    tcp.set_sequence(seq);
    tcp.set_acknowledgement(ack);
    tcp.set_flags(flags);
    tcp.set_data_offset(TCP_HEADER_LEN as u8 / 4 + wscale as u8);
    if wscale {
        let wscale = tcp::TcpOption::wscale(14);
        tcp.set_options(&[tcp::TcpOption::nop(), wscale]);
    }

    if let Some(payload) = payload {
        tcp.set_payload(payload);
    }

    let mut cksm = Checksum::new();
    let ip::IpNextHeaderProtocol(tcp_protocol) = ip::IpNextHeaderProtocols::Tcp;

    match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            cksm.add_bytes(&local.ip().octets());
            cksm.add_bytes(&remote.ip().octets());

            let mut pseudo = [0u8, tcp_protocol, 0, 0];
            pseudo[2..].copy_from_slice(&(tcp_total_len as u16).to_be_bytes());
            cksm.add_bytes(&pseudo);
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            cksm.add_bytes(&local.ip().octets());
            cksm.add_bytes(&remote.ip().octets());

            let mut pseudo = [0u8, 0, 0, 0, 0, 0, 0, tcp_protocol];
            pseudo[0..4].copy_from_slice(&(tcp_total_len as u32).to_be_bytes());
            cksm.add_bytes(&pseudo);
        }
        _ => unreachable!(),
    };

    cksm.add_bytes(tcp.packet());
    tcp.set_checksum(u16::from_be_bytes(cksm.checksum()));

    Ok(total_len + offset)
}

pub fn parse_ip_packet(buf: &[u8]) -> Option<(IPPacket, tcp::TcpPacket)> {
    if buf.is_empty() {
        return None;
    }

    #[cfg(any(
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios"
    ))]
    let buf = &buf[4..];
    #[cfg(not(any(
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios"
    )))]
    let buf = &buf;

    if buf[0] >> 4 == 4 {
        let v4 = ipv4::Ipv4Packet::new(buf)?;
        if v4.get_next_level_protocol() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(&buf[IPV4_HEADER_LEN..])?;
        Some((IPPacket::V4(v4), tcp))
    } else if buf[0] >> 4 == 6 {
        let v6 = ipv6::Ipv6Packet::new(buf)?;
        if v6.get_next_header() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(&buf[IPV6_HEADER_LEN..])?;
        Some((IPPacket::V6(v6), tcp))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::tcp;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn build_and_parse_ipv4_packet_round_trip() {
        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1111));
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 2222));
        let payload = [1u8, 2, 3, 4];
        let mut buf = [0u8; MAX_PACKET_LEN];

        let size = build_tcp_packet(
            &mut buf,
            local_addr,
            remote_addr,
            123,
            456,
            tcp::TcpFlags::ACK,
            Some(&payload),
        )
        .unwrap();

        let (ip_packet, tcp_packet) = parse_ip_packet(&buf[..size]).unwrap();
        assert_eq!(ip_packet.get_source(), local_addr.ip());
        assert_eq!(ip_packet.get_destination(), remote_addr.ip());
        assert_eq!(tcp_packet.get_source(), local_addr.port());
        assert_eq!(tcp_packet.get_destination(), remote_addr.port());
        assert_eq!(tcp_packet.get_sequence(), 123);
        assert_eq!(tcp_packet.get_acknowledgement(), 456);
        assert_eq!(tcp_packet.get_flags(), tcp::TcpFlags::ACK);
        assert_eq!(tcp_packet.payload(), &payload);
    }

    #[test]
    fn build_and_parse_ipv6_packet_round_trip() {
        let local_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1111, 0, 0));
        let remote_addr = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::1".parse().unwrap(),
            2222,
            0,
            0,
        ));
        let payload = [9u8, 8, 7];
        let mut buf = [0u8; MAX_PACKET_LEN];

        let size = build_tcp_packet(
            &mut buf,
            local_addr,
            remote_addr,
            321,
            654,
            tcp::TcpFlags::ACK,
            Some(&payload),
        )
        .unwrap();

        let (ip_packet, tcp_packet) = parse_ip_packet(&buf[..size]).unwrap();
        assert_eq!(ip_packet.get_source(), local_addr.ip());
        assert_eq!(ip_packet.get_destination(), remote_addr.ip());
        assert_eq!(tcp_packet.get_source(), local_addr.port());
        assert_eq!(tcp_packet.get_destination(), remote_addr.port());
        assert_eq!(tcp_packet.get_sequence(), 321);
        assert_eq!(tcp_packet.get_acknowledgement(), 654);
        assert_eq!(tcp_packet.get_flags(), tcp::TcpFlags::ACK);
        assert_eq!(tcp_packet.payload(), &payload);
    }

    #[test]
    fn build_tcp_packet_rejects_too_small_buffer() {
        let local_addr: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.2:2222".parse().unwrap();
        let payload = [1u8; 32];
        let mut buf = [0u8; 8];

        let result = build_tcp_packet(
            &mut buf,
            local_addr,
            remote_addr,
            1,
            2,
            tcp::TcpFlags::ACK,
            Some(&payload),
        );

        assert!(result.is_err());
    }

    #[test]
    fn parse_ip_packet_returns_none_for_empty_buffer() {
        assert!(parse_ip_packet(&[]).is_none());
    }

    #[test]
    fn parse_ip_packet_returns_none_for_non_tcp_ipv4_packet() {
        let mut buf = [0u8; 20];
        let mut packet = ipv4::MutableIpv4Packet::new(&mut buf).unwrap();
        packet.set_version(4);
        packet.set_header_length(5);
        packet.set_total_length(20);
        packet.set_next_level_protocol(ip::IpNextHeaderProtocols::Udp);

        assert!(parse_ip_packet(&buf).is_none());
    }

    #[test]
    fn parse_ip_packet_returns_none_for_non_tcp_ipv6_packet() {
        let mut buf = [0u8; IPV6_HEADER_LEN];
        let mut packet = ipv6::MutableIpv6Packet::new(&mut buf).unwrap();
        packet.set_version(6);
        packet.set_payload_length(0);
        packet.set_next_header(ip::IpNextHeaderProtocols::Udp);

        assert!(parse_ip_packet(&buf).is_none());
    }

    #[test]
    fn build_syn_packet_sets_tcp_options_length() {
        let local_addr: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.2:2222".parse().unwrap();
        let mut buf = [0u8; MAX_PACKET_LEN];

        let size = build_tcp_packet(
            &mut buf,
            local_addr,
            remote_addr,
            10,
            0,
            tcp::TcpFlags::SYN,
            None,
        )
        .unwrap();

        let (_, tcp_packet) = parse_ip_packet(&buf[..size]).unwrap();
        assert_eq!(tcp_packet.get_flags(), tcp::TcpFlags::SYN);
        assert_eq!(tcp_packet.get_data_offset(), 6);
    }

    #[test]
    fn build_and_parse_ipv4_packet_without_payload() {
        let local_addr: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.2:2222".parse().unwrap();
        let mut buf = [0u8; MAX_PACKET_LEN];

        let size = build_tcp_packet(
            &mut buf,
            local_addr,
            remote_addr,
            123,
            456,
            tcp::TcpFlags::ACK,
            None,
        )
        .unwrap();

        let (_, tcp_packet) = parse_ip_packet(&buf[..size]).unwrap();
        assert!(tcp_packet.payload().is_empty());
    }

    #[test]
    fn build_tcp_packet_accepts_max_ipv4_payload_that_fits_buffer() {
        let local_addr: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.2:2222".parse().unwrap();
        let payload = [7u8; MAX_PACKET_LEN - IPV4_HEADER_LEN - TCP_HEADER_LEN];
        let mut buf = [0u8; MAX_PACKET_LEN];

        let size = build_tcp_packet(
            &mut buf,
            local_addr,
            remote_addr,
            123,
            456,
            tcp::TcpFlags::ACK,
            Some(&payload),
        )
        .unwrap();

        assert_eq!(size, MAX_PACKET_LEN);
        let (_, tcp_packet) = parse_ip_packet(&buf[..size]).unwrap();
        assert_eq!(tcp_packet.payload(), &payload);
    }

    #[test]
    fn parse_ip_packet_returns_none_for_invalid_ip_version() {
        let buf = [0x70, 0, 0, 0];

        assert!(parse_ip_packet(&buf).is_none());
    }

    #[test]
    fn parse_ip_packet_returns_none_for_truncated_ipv4_tcp_packet() {
        let local_addr: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.2:2222".parse().unwrap();
        let mut buf = [0u8; MAX_PACKET_LEN];
        let size = build_tcp_packet(
            &mut buf,
            local_addr,
            remote_addr,
            123,
            456,
            tcp::TcpFlags::ACK,
            None,
        )
        .unwrap();

        assert!(parse_ip_packet(&buf[..size - 1]).is_none());
    }

    #[test]
    fn build_tcp_packet_rejects_payload_exceeding_max_packet_size() {
        let local_addr: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.2:2222".parse().unwrap();
        let extra_offset = if cfg!(any(
            target_os = "openbsd",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "macos",
            target_os = "ios"
        )) {
            4
        } else {
            0
        };
        let payload_len = MAX_PACKET_LEN - IPV4_HEADER_LEN - TCP_HEADER_LEN - extra_offset + 1;
        let payload = vec![7u8; payload_len];
        let mut buf = [0u8; MAX_PACKET_LEN];

        let result = build_tcp_packet(
            &mut buf,
            local_addr,
            remote_addr,
            123,
            456,
            tcp::TcpFlags::ACK,
            Some(payload.as_slice()),
        );

        assert!(result.is_err());
    }

    #[test]
    fn parse_ip_packet_returns_none_for_ipv4_header_length_larger_than_buffer() {
        let mut buf = [0u8; IPV4_HEADER_LEN];
        buf[0] = (4 << 4) | 6;

        assert!(parse_ip_packet(&buf).is_none());
    }

    #[test]
    fn parse_ip_packet_returns_none_for_ipv6_buffer_too_short_for_header() {
        let buf = [0x60u8; IPV6_HEADER_LEN - 1];

        assert!(parse_ip_packet(&buf).is_none());
    }

    #[test]
    fn parse_ip_packet_returns_none_for_truncated_ipv6_tcp_packet() {
        let local_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1111, 0, 0));
        let remote_addr = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::1".parse().unwrap(),
            2222,
            0,
            0,
        ));
        let mut buf = [0u8; MAX_PACKET_LEN];
        let size = build_tcp_packet(
            &mut buf,
            local_addr,
            remote_addr,
            321,
            654,
            tcp::TcpFlags::ACK,
            Some(&[1u8, 2, 3]),
        )
        .unwrap();

        let truncated_size = size - TCP_HEADER_LEN;
        assert!(parse_ip_packet(&buf[..truncated_size]).is_none());
    }
}

#[cfg(all(test, feature = "benchmark"))]
mod benchmarks {
    use super::*;
    use std::hint::black_box;
    use std::time::Instant;

    const ITERATIONS: usize = 10_000;

    fn run_build_tcp_packet_bench(payload_len: usize) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = vec![123u8; payload_len];
        let mut buf = [0u8; MAX_PACKET_LEN];
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let size = build_tcp_packet(
                &mut buf,
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(payload.as_slice()),
            )
            .unwrap();
            black_box(size);
        }
        eprintln!(
            "build_tcp_packet payload_len={payload_len} iterations={ITERATIONS} elapsed={:?}",
            start.elapsed()
        );
    }

    #[test]
    #[ignore = "microbenchmark"]
    fn bench_build_tcp_packet_1460() {
        run_build_tcp_packet_bench(1460);
    }

    #[test]
    #[ignore = "microbenchmark"]
    fn bench_build_tcp_packet_512() {
        run_build_tcp_packet_bench(512);
    }

    #[test]
    #[ignore = "microbenchmark"]
    fn bench_build_tcp_packet_128() {
        run_build_tcp_packet_bench(128);
    }
}
