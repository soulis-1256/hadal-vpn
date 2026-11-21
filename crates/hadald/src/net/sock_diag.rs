use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;

const NLMSG_HDRLEN: usize = 16;
const INET_DIAG_SOCKID_LEN: usize = 48;
const INET_DIAG_REQ_V2_LEN: usize = 56;
const INET_DIAG_MSG_LEN: usize = 72;

// Linux kernel TCP/UDP socket states (`include/net/tcp_states.h`)
const TCP_ESTABLISHED: u8 = 1;
const TCP_SYN_SENT: u8 = 2;
const TCP_SYN_RECV: u8 = 3;
const TCP_CLOSE: u8 = 7; // Kernel uses TCP_CLOSE (7) for unconnected (UNCONN) UDP sockets

const TCP_ACTIVE_STATES: u32 = (1 << TCP_ESTABLISHED) | (1 << TCP_SYN_SENT) | (1 << TCP_SYN_RECV);
const UDP_TARGET_STATES: u32 = (1 << TCP_ESTABLISHED) | (1 << TCP_CLOSE);

/// Abstraction over `NETLINK_SOCK_DIAG` socket handoff across split-tunnel transitions.
pub trait SockDiagBackend: Send + Sync {
    fn reset_app_sockets(&self, pids: &[u32]) -> usize;
}

/// Real kernel `NETLINK_SOCK_DIAG` (`SOCK_DESTROY`) backend.
pub struct NetlinkSockDiag;

impl SockDiagBackend for NetlinkSockDiag {
    fn reset_app_sockets(&self, pids: &[u32]) -> usize {
        reset_app_sockets(pids)
    }
}

#[derive(Debug, Clone)]
struct DiagTarget {
    family: u8,
    protocol: u8,
    state: u8,
    sockid: [u8; INET_DIAG_SOCKID_LEN],
}

fn align_nlmsg(len: usize) -> usize {
    (len + 3) & !3
}

fn collect_pid_socket_inodes(pids: &[u32]) -> HashSet<u64> {
    let mut inodes = HashSet::new();
    for pid in pids {
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(entries) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Ok(link) = std::fs::read_link(entry.path()) {
                let s = link.to_string_lossy();
                if let Some(num) = s.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
                    if let Ok(ino) = num.parse::<u64>() {
                        if ino != 0 {
                            inodes.insert(ino);
                        }
                    }
                }
            }
        }
    }
    inodes
}

fn is_loopback_diag_addr(family: u8, addr: &[u8; 16]) -> bool {
    match family as i32 {
        libc::AF_INET => Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).is_loopback(),
        libc::AF_INET6 => {
            let v6 = Ipv6Addr::from(*addr);
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        _ => false,
    }
}

/// Inspect a kernel `inet_diag_msg` payload (`>= 72` bytes) and return a destroy target
/// if it belongs to `inodes` and is an eligible WAN flow.
fn parse_diag_target(msg: &[u8], protocol: u8, inodes: &HashSet<u64>) -> Option<DiagTarget> {
    if msg.len() < INET_DIAG_MSG_LEN {
        return None;
    }

    let family = msg[0];
    let state = msg[1];
    let inode = u32::from_ne_bytes(msg[68..72].try_into().ok()?) as u64;
    if inode == 0 || !inodes.contains(&inode) {
        return None;
    }

    let sockid: [u8; INET_DIAG_SOCKID_LEN] = msg[4..52].try_into().ok()?;
    let sport = u16::from_be_bytes([sockid[0], sockid[1]]);
    let dport = u16::from_be_bytes([sockid[2], sockid[3]]);
    let src: [u8; 16] = sockid[4..20].try_into().ok()?;
    let dst: [u8; 16] = sockid[20..36].try_into().ok()?;

    if is_loopback_diag_addr(family, &src) || is_loopback_diag_addr(family, &dst) {
        return None;
    }

    match protocol as i32 {
        libc::IPPROTO_TCP => {
            if !matches!(state, TCP_ESTABLISHED | TCP_SYN_SENT | TCP_SYN_RECV)
                || sport == 0
                || dport == 0
            {
                return None;
            }
        }
        libc::IPPROTO_UDP => {
            if state == TCP_ESTABLISHED {
                if sport == 0 || dport == 0 {
                    return None;
                }
            } else if state == TCP_CLOSE && dport == 0 {
                // Keep well-known control/discovery ports intact while resetting QUIC/game flows
                if sport == 0 || matches!(sport, 53 | 67 | 68 | 123 | 546 | 547 | 5353 | 5355) {
                    return None;
                }
            } else {
                return None;
            }
        }
        _ => return None,
    }

    Some(DiagTarget {
        family,
        protocol,
        state,
        sockid,
    })
}

fn build_diag_packet(
    msg_type: u16,
    flags: u16,
    seq: u32,
    family: u8,
    protocol: u8,
    states: u32,
    sockid: &[u8; INET_DIAG_SOCKID_LEN],
) -> [u8; NLMSG_HDRLEN + INET_DIAG_REQ_V2_LEN] {
    let total_len = (NLMSG_HDRLEN + INET_DIAG_REQ_V2_LEN) as u32;
    let mut pkt = [0u8; NLMSG_HDRLEN + INET_DIAG_REQ_V2_LEN];

    pkt[0..4].copy_from_slice(&total_len.to_ne_bytes());
    pkt[4..6].copy_from_slice(&msg_type.to_ne_bytes());
    pkt[6..8].copy_from_slice(&flags.to_ne_bytes());
    pkt[8..12].copy_from_slice(&seq.to_ne_bytes());

    let req = &mut pkt[NLMSG_HDRLEN..];
    req[0] = family;
    req[1] = protocol;
    req[2] = 0;
    req[3] = 0;
    req[4..8].copy_from_slice(&states.to_ne_bytes());
    req[8..56].copy_from_slice(sockid);
    pkt
}

fn open_sock_diag() -> io::Result<OwnedFd> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let tv = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    Ok(fd)
}

fn nl_send_all(fd: &OwnedFd, buf: &[u8]) -> io::Result<()> {
    loop {
        let rc = unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0) };
        if rc >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn nl_recv(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let rc = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn dump_matching_sockets(
    fd: &OwnedFd,
    seq: &mut u32,
    family: u8,
    protocol: u8,
    states: u32,
    inodes: &HashSet<u64>,
    out: &mut Vec<DiagTarget>,
) -> io::Result<()> {
    *seq += 1;
    let empty_id = [0u8; INET_DIAG_SOCKID_LEN];
    let req = build_diag_packet(
        SOCK_DIAG_BY_FAMILY,
        (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
        *seq,
        family,
        protocol,
        states,
        &empty_id,
    );
    nl_send_all(fd, &req)?;

    let mut recv_buf = vec![0u8; 65536];
    loop {
        let n = nl_recv(fd, &mut recv_buf)?;
        if n == 0 {
            break;
        }
        let mut off = 0usize;
        let mut done = false;
        while off + NLMSG_HDRLEN <= n {
            let mlen = u32::from_ne_bytes(recv_buf[off..off + 4].try_into().unwrap()) as usize;
            let mtype = u16::from_ne_bytes(recv_buf[off + 4..off + 6].try_into().unwrap());
            if mlen < NLMSG_HDRLEN || off + mlen > n {
                break;
            }
            if mtype == libc::NLMSG_DONE as u16 {
                done = true;
                break;
            }
            if mtype == libc::NLMSG_ERROR as u16 {
                return Ok(());
            }
            if mtype == SOCK_DIAG_BY_FAMILY {
                let payload = &recv_buf[off + NLMSG_HDRLEN..off + mlen];
                if let Some(target) = parse_diag_target(payload, protocol, inodes) {
                    out.push(target);
                }
            }
            off += align_nlmsg(mlen);
        }
        if done {
            break;
        }
    }
    Ok(())
}

fn destroy_target(fd: &OwnedFd, seq: &mut u32, target: &DiagTarget) -> bool {
    *seq += 1;
    let req = build_diag_packet(
        SOCK_DESTROY,
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
        *seq,
        target.family,
        target.protocol,
        1u32 << target.state,
        &target.sockid,
    );
    if nl_send_all(fd, &req).is_err() {
        return false;
    }

    let mut ack = [0u8; 4096];
    let Ok(n) = nl_recv(fd, &mut ack) else {
        return false;
    };
    if n < NLMSG_HDRLEN + 4 {
        return false;
    }
    let mtype = u16::from_ne_bytes(ack[4..6].try_into().unwrap());
    if mtype != libc::NLMSG_ERROR as u16 {
        return false;
    }
    let err = i32::from_ne_bytes(ack[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap());
    err == 0
}

/// Abort pre-existing WAN TCP/UDP sockets (IPv4, IPv6, and unconnected QUIC/HTTP3 sockets)
/// owned by PIDs that just migrated across split-tunnel cgroups, using kernel `NETLINK_SOCK_DIAG`
/// (`SOCK_DESTROY` with exact 64-bit socket cookies) in-process.
pub fn reset_app_sockets(pids: &[u32]) -> usize {
    if pids.is_empty() {
        return 0;
    }
    let inodes = collect_pid_socket_inodes(pids);
    if inodes.is_empty() {
        return 0;
    }

    let Ok(fd) = open_sock_diag() else {
        return 0;
    };

    let mut seq = 0u32;
    let mut targets = Vec::new();
    for (family, protocol, states) in [
        (libc::AF_INET as u8, libc::IPPROTO_TCP as u8, TCP_ACTIVE_STATES),
        (libc::AF_INET6 as u8, libc::IPPROTO_TCP as u8, TCP_ACTIVE_STATES),
        (libc::AF_INET as u8, libc::IPPROTO_UDP as u8, UDP_TARGET_STATES),
        (libc::AF_INET6 as u8, libc::IPPROTO_UDP as u8, UDP_TARGET_STATES),
    ] {
        let _ = dump_matching_sockets(&fd, &mut seq, family, protocol, states, &inodes, &mut targets);
    }

    targets
        .iter()
        .filter(|target| destroy_target(&fd, &mut seq, target))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeDiagMsg {
        family: u8,
        state: u8,
        sport: u16,
        dport: u16,
        src: [u8; 16],
        dst: [u8; 16],
        cookie: [u32; 2],
        inode: u32,
    }

    impl FakeDiagMsg {
        fn encode(&self) -> [u8; INET_DIAG_MSG_LEN] {
            let mut msg = [0u8; INET_DIAG_MSG_LEN];
            msg[0] = self.family;
            msg[1] = self.state;
            msg[4..6].copy_from_slice(&self.sport.to_be_bytes());
            msg[6..8].copy_from_slice(&self.dport.to_be_bytes());
            msg[8..24].copy_from_slice(&self.src);
            msg[24..40].copy_from_slice(&self.dst);
            msg[44..48].copy_from_slice(&self.cookie[0].to_ne_bytes());
            msg[48..52].copy_from_slice(&self.cookie[1].to_ne_bytes());
            msg[68..72].copy_from_slice(&self.inode.to_ne_bytes());
            msg
        }
    }

    fn v4_slot(ip: Ipv4Addr) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&ip.octets());
        b
    }

    #[test]
    fn filters_and_extracts_tcp_ipv6_and_unconnected_quic_cookies() {
        let inodes = HashSet::from([101u64, 102, 103, 104, 105, 106]);

        let tcp4 = FakeDiagMsg {
            family: libc::AF_INET as u8,
            state: TCP_ESTABLISHED,
            sport: 51800,
            dport: 443,
            src: v4_slot(Ipv4Addr::new(10, 14, 0, 2)),
            dst: v4_slot(Ipv4Addr::new(142, 251, 155, 119)),
            cookie: [0xdead_beef, 0x1234_5678],
            inode: 101,
        }
        .encode();
        let t1 = parse_diag_target(&tcp4, libc::IPPROTO_TCP as u8, &inodes)
            .expect("IPv4 TCP matched");
        assert_eq!(t1.family, libc::AF_INET as u8);
        assert_eq!(&t1.sockid[40..44], &0xdead_beefu32.to_ne_bytes());

        let src6 = "2a02:85f:eca4:6101:7a7d:e135:b9b6:1b6f"
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets();
        let dst6 = "2a04:4e42:4d::347".parse::<Ipv6Addr>().unwrap().octets();
        let tcp6 = FakeDiagMsg {
            family: libc::AF_INET6 as u8,
            state: TCP_ESTABLISHED,
            sport: 36612,
            dport: 443,
            src: src6,
            dst: dst6,
            cookie: [11, 22],
            inode: 102,
        }
        .encode();
        assert!(parse_diag_target(&tcp6, libc::IPPROTO_TCP as u8, &inodes).is_some());

        let udp_unconn = FakeDiagMsg {
            family: libc::AF_INET as u8,
            state: TCP_CLOSE,
            sport: 33489,
            dport: 0,
            src: [0; 16],
            dst: [0; 16],
            cookie: [0x40, 0],
            inode: 103,
        }
        .encode();
        let t3 = parse_diag_target(&udp_unconn, libc::IPPROTO_UDP as u8, &inodes)
            .expect("HTTP/3 UNCONN UDP matched");
        assert_eq!(t3.state, TCP_CLOSE);

        let lo_v4 = FakeDiagMsg {
            family: libc::AF_INET as u8,
            state: TCP_ESTABLISHED,
            sport: 40000,
            dport: 1234,
            src: v4_slot(Ipv4Addr::LOCALHOST),
            dst: v4_slot(Ipv4Addr::LOCALHOST),
            cookie: [1, 1],
            inode: 104,
        }
        .encode();
        assert!(parse_diag_target(&lo_v4, libc::IPPROTO_TCP as u8, &inodes).is_none());

        let mapped_lo = Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets();
        let lo_v6_mapped = FakeDiagMsg {
            family: libc::AF_INET6 as u8,
            state: TCP_ESTABLISHED,
            sport: 40001,
            dport: 1234,
            src: mapped_lo,
            dst: mapped_lo,
            cookie: [2, 2],
            inode: 105,
        }
        .encode();
        assert!(parse_diag_target(&lo_v6_mapped, libc::IPPROTO_TCP as u8, &inodes).is_none());

        let mdns = FakeDiagMsg {
            family: libc::AF_INET as u8,
            state: TCP_CLOSE,
            sport: 5353,
            dport: 0,
            src: [0; 16],
            dst: [0; 16],
            cookie: [3, 3],
            inode: 106,
        }
        .encode();
        assert!(parse_diag_target(&mdns, libc::IPPROTO_UDP as u8, &inodes).is_none());
    }
}
