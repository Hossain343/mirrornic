use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

static DLL: &[u8] = include_bytes!("../assets/wintun.dll");

/// A resolved physical exit interface. Every relay/probe socket is double-locked
/// onto it: `IP_UNICAST_IF` (forces the outgoing NIC regardless of the routing
/// table — this is what defeats a VPN's default route) *and* a source-IP bind.
#[derive(Clone)]
pub struct Exit {
    pub idx: u32,
    pub ip: Option<Ipv4Addr>,
    pub name: String,
}

pub struct Engine {
    session: Arc<wintun::Session>,
    thread: Option<std::thread::JoinHandle<()>>,
    rt: Option<Runtime>,
    _adapter: Arc<wintun::Adapter>,
    _wintun: wintun::Wintun,
    /// Human-readable note about the exit interface that was picked
    /// (includes warnings, e.g. when a VPN adapter had to be skipped).
    pub note: String,
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.session.shutdown();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_millis(500));
        }
    }
}

fn netsh(args: &[&str]) -> bool {
    Command::new("netsh")
        .args(args)
        .creation_flags(0x0800_0000)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn configure(name: &str, route: &str) {
    let n = format!("name={}", name);
    for _ in 0..40 {
        if netsh(&["interface", "ip", "set", "address", &n, "static", "10.66.0.2", "255.255.255.0"]) {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let i = format!("interface={}", name);
    // Lowest possible interface metric so our default route beats a VPN's.
    if !netsh(&["interface", "ipv4", "set", "interface", &i, "metric=0"]) {
        netsh(&["interface", "ipv4", "set", "interface", &i, "metric=1"]);
    }
    netsh(&["interface", "ipv4", "set", "subinterface", name, "mtu=1500", "store=active"]);
    for r in route.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let p = format!("prefix={}", r);
        // Route metric 0 (effective metric = interface metric) — fall back to 1
        // if this netsh build rejects 0.
        if !netsh(&["interface", "ipv4", "add", "route", &p, &i, "nexthop=0.0.0.0", "metric=0", "store=active"]) {
            netsh(&["interface", "ipv4", "add", "route", &p, &i, "nexthop=0.0.0.0", "metric=1", "store=active"]);
        }
    }
    netsh(&["interface", "ip", "set", "dns", &n, "static", "1.1.1.1", "validate=no"]);
    netsh(&["interface", "ip", "add", "dns", &n, "8.8.8.8", "index=2", "validate=no"]);
}

// ---------------------------------------------------------------------------
// Interface enumeration (GetAdaptersAddresses) — VPN-aware exit selection.
// ---------------------------------------------------------------------------

struct AdapterInfo {
    idx: u32,
    name: String,
    desc: String,
    ip: Option<Ipv4Addr>,
    if_type: u32,
    oper: i32,
    metric: u32,
    has_gw: bool,
}

fn wide(p: *mut u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut n = 0usize;
        while n < 512 && *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

fn adapters() -> Vec<AdapterInfo> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    const FLAGS: u32 = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    unsafe {
        let mut size: u32 = 0;
        let _ = GetAdaptersAddresses(
            AF_INET as u32,
            FLAGS,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        );
        if size == 0 {
            size = 64 * 1024;
        }
        let mut out: Vec<AdapterInfo> = Vec::new();
        for _ in 0..4 {
            let mut buf: Vec<u64> = vec![0u64; (size as usize + 7) / 8];
            let base = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            let r = GetAdaptersAddresses(AF_INET as u32, FLAGS, std::ptr::null(), base, &mut size);
            if r == 111 {
                continue; // ERROR_BUFFER_OVERFLOW — retry with the new size
            }
            if r != 0 {
                break;
            }
            let mut cur = base;
            while !cur.is_null() {
                let a = &*cur;
                let raw_idx = a.Anonymous1.Anonymous.IfIndex;
                let idx = if raw_idx != 0 { raw_idx } else { a.Ipv6IfIndex };

                // First usable unicast IPv4 address of this adapter.
                let mut ip: Option<Ipv4Addr> = None;
                let mut u = a.FirstUnicastAddress;
                while !u.is_null() {
                    let ua = &*u;
                    let sa = ua.Address.lpSockaddr;
                    if !sa.is_null()
                        && ua.Address.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN>()
                    {
                        let sin = sa as *const SOCKADDR_IN;
                        if (*sin).sin_family == AF_INET {
                            let mut b = [0u8; 4];
                            std::ptr::copy_nonoverlapping(
                                &(*sin).sin_addr as *const _ as *const u8,
                                b.as_mut_ptr(),
                                4,
                            );
                            let cand = Ipv4Addr::from(b);
                            if !cand.is_unspecified() && !cand.is_loopback() {
                                ip = Some(cand);
                                break;
                            }
                        }
                    }
                    u = ua.Next;
                }

                out.push(AdapterInfo {
                    idx,
                    name: wide(a.FriendlyName),
                    desc: wide(a.Description),
                    ip,
                    if_type: a.IfType,
                    oper: a.OperStatus,
                    metric: a.Ipv4Metric,
                    has_gw: !a.FirstGatewayAddress.is_null(),
                });
                cur = a.Next;
            }
            return out;
        }
        out
    }
}

/// IF_TYPE_ETHERNET / IF_TYPE_IEEE80211 — real wired / Wi-Fi NICs.
fn is_phys_type(t: u32) -> bool {
    matches!(t, 6 | 71)
}

fn is_loopback(a: &AdapterInfo) -> bool {
    let s = format!("{} {}", a.name, a.desc).to_lowercase();
    a.if_type == 24 || s.contains("loopback")
}

/// Heuristic name/description check for VPN, tunnel and virtual adapters.
/// (Type filtering already excludes most tunnels; this catches virtual NICs
/// that report themselves as plain Ethernet, e.g. VMware/VBox/Hyper-V/GCP.)
fn looks_virtual(a: &AdapterInfo) -> bool {
    let s = format!("{} {}", a.name, a.desc).to_lowercase();
    const BAD: &[&str] = &[
        "vpn", "tun", "tap", "wintun", "wireguard", "hotspot", "shield", "openvpn",
        "nord", "proton", "mullvad", "expressvpn", "hyper-v", "vethernet", "virtual",
        "vmware", "vbox", "virtualbox", "isatap", "teredo", "mirrornic", "wan miniport",
        "bluetooth", "wi-fi direct", "wifi direct", "hosted network", "microsoft kern",
        "zscaler", "tailscale", "zerotier", "hamachi", "anyconnect", "forticlient",
        "sstp", "l2tp", "pptp", "ikev", "softether", "outline", "gvt1", "packet scheduler",
    ];
    BAD.iter().any(|b| s.contains(b))
}

fn is_physical(a: &AdapterInfo) -> bool {
    is_phys_type(a.if_type) && !looks_virtual(a)
}

fn rank(a: &AdapterInfo) -> (u8, u32) {
    // Prefer adapters that have a default gateway, then the lowest metric.
    (if a.has_gw { 0 } else { 1 }, a.metric)
}

fn pick(all: &[AdapterInfo], f: impl Fn(&AdapterInfo) -> bool) -> Option<Exit> {
    let mut v: Vec<&AdapterInfo> = all.iter().filter(|a| a.idx != 0 && f(a)).collect();
    v.sort_by_key(|a| rank(a));
    v.into_iter().next().map(|a| Exit {
        idx: a.idx,
        ip: a.ip,
        name: a.name.clone(),
    })
}

/// Resolve the physical exit interface.
///
/// `sel = None` (Auto) deliberately IGNORES the routing table — that is the
/// whole point: `GetBestInterface(8.8.8.8)` returns the VPN's tunnel adapter
/// when a VPN owns the default route, which used to force every relayed socket
/// *into* the tunnel. Instead we pick a physical (Ethernet/802.11) NIC with a
/// live IPv4 address and a gateway.
///
/// A manually selected VPN/tunnel adapter is rejected with a warning and the
/// physical NIC is used instead.
pub fn resolve_exit(sel: Option<u32>) -> Result<(Exit, String), String> {
    let all = adapters();
    if all.is_empty() {
        return Err("cannot list network adapters".to_string());
    }

    // Auto selection tiers (most strict first).
    let best = pick(&all, |a| is_physical(a) && a.oper == 1 && a.ip.is_some())
        .or_else(|| pick(&all, |a| is_physical(a) && a.ip.is_some()))
        .or_else(|| pick(&all, |a| is_physical(a)))
        .or_else(|| pick(&all, |a| !is_loopback(a) && a.ip.is_some()))
        .or_else(|| pick(&all, |a| !is_loopback(a)))
        .ok_or_else(|| "no usable network adapter found".to_string())?;
    let best_note = format!("{} (#{})", best.name, best.idx);

    if let Some(want) = sel {
        if let Some(a) = all.iter().find(|a| a.idx == want) {
            if is_physical(a) {
                let note = format!("{} (#{})", a.name, a.idx);
                let exit = Exit { idx: a.idx, ip: a.ip, name: a.name.clone() };
                return Ok((exit, note));
            }
            let note = format!(
                "{} — '{}' is a VPN/tunnel adapter, switched to physical",
                best_note, a.name
            );
            return Ok((best, note));
        }
        let note = format!("{} — selected exit #{} no longer exists", best_note, want);
        return Ok((best, note));
    }

    Ok((best, best_note))
}

/// All non-loopback IPv4 adapters for the UI. Non-physical ones are tagged so
/// the user can see at a glance which entries are VPN/virtual.
pub fn list_ifaces() -> Vec<(u32, String)> {
    adapters()
        .into_iter()
        .filter(|a| a.idx != 0 && !is_loopback(a))
        .map(|a| {
            let tag = if is_physical(a) { "" } else { " [VPN/virtual]" };
            (a.idx, format!("{}{}", a.name, tag))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Forcing sockets onto the physical interface.
// ---------------------------------------------------------------------------

/// Force a socket out of interface `idx`.
///
/// `IP_UNICAST_IF` takes the index in **network byte order** for IPv4
/// (see Microsoft's IPPROTO_IP socket-options doc; libtorrent, tun2socks,
/// etc. all byte-swap). This overrides the routing table for this socket,
/// which is exactly what is needed when a VPN has hijacked the default route.
/// The return value of setsockopt is checked; a host-order fallback is tried
/// in case a stack rejects the documented form.
fn set_unicast_if(raw: u64, idx: u32) -> bool {
    use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IP_UNICAST_IF};
    if idx == 0 {
        return false;
    }
    let be = idx.to_be();
    unsafe {
        if setsockopt(
            raw as usize,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &be as *const u32 as *const u8,
            4,
        ) == 0
        {
            return true;
        }
        // Fallback: host byte order (some stacks are lenient).
        setsockopt(
            raw as usize,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &idx as *const u32 as *const u8,
            4,
        ) == 0
    }
}

// ---------------------------------------------------------------------------
// Probes used by the UI "Test" button.
// ---------------------------------------------------------------------------

const IP_HOSTS: [&str; 4] = [
    "api.ipify.org",
    "checkip.amazonaws.com",
    "icanhazip.com",
    "ip.seeip.org",
];

fn try_connect(host: &str, addr: SocketAddr, force: Option<&Exit>) -> Result<String, String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| e.to_string())?;
    if let Some(ex) = force {
        set_unicast_if(s.as_raw_socket(), ex.idx);
        if let Some(ip) = ex.ip {
            let _ = s.bind(&SockAddr::from(SocketAddrV4::new(ip, 0)));
        }
    }
    s.connect_timeout(&SockAddr::from(addr), Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    let raw = s.into_raw_socket();
    let mut ts = unsafe { std::net::TcpStream::from_raw_socket(raw) };
    ts.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    ts.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    write!(
        ts,
        "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let mut buf = String::new();
    ts.read_to_string(&mut buf).map_err(|e| e.to_string())?;
    let body = buf
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| "empty response".to_string())?
        .trim()
        .to_string();
    if body.parse::<Ipv4Addr>().is_ok() {
        Ok(body)
    } else {
        Err(format!(
            "unexpected body: {}",
            body.chars().take(40).collect::<String>()
        ))
    }
}

/// Fetch the public IP. With `force = Some(exit)` the socket is double-locked
/// onto the physical NIC, so the result is the IP of the *real* egress path
/// even while a VPN owns the system default route.
fn fetch_ip(force: Option<&Exit>) -> Result<String, String> {
    let mut last = "no host".to_string();
    for h in IP_HOSTS {
        let addrs: Vec<SocketAddr> = match (h, 80).to_socket_addrs() {
            Ok(a) => a.filter(|x| x.is_ipv4()).collect(),
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        for addr in addrs {
            match try_connect(h, addr, force) {
                Ok(ip) => return Ok(ip),
                Err(e) => last = e,
            }
        }
    }
    Err(last)
}

/// Two-probe report for the UI:
///   direct — socket locked to the physical exit NIC (the path MirrorNIC uses)
///   system — plain socket, whatever Windows would do (VPN, when present)
/// Different IPs prove the bypass is working.
pub fn probe_report(sel: Option<u32>) -> String {
    let direct = match resolve_exit(sel) {
        Ok((ex, _)) => match fetch_ip(Some(&ex)) {
            Ok(ip) => format!("direct: {} [{}]", ip, ex.name),
            Err(e) => format!("direct: FAILED ({e})"),
        },
        Err(e) => format!("direct: {e}"),
    };
    let system = match fetch_ip(None) {
        Ok(ip) => format!("system: {}", ip),
        Err(e) => format!("system: FAILED ({e})"),
    };
    let d = direct
        .strip_prefix("direct: ")
        .and_then(|s| s.split_whitespace().next())
        .and_then(|t| t.parse::<Ipv4Addr>().ok());
    let s = system
        .strip_prefix("system: ")
        .and_then(|s| s.split_whitespace().next())
        .and_then(|t| t.parse::<Ipv4Addr>().ok());
    let verdict = match (d, s) {
        (Some(a), Some(b)) if a == b => "same path (no VPN between us and the internet)",
        (Some(_), Some(_)) => "bypass OK — direct traffic leaves the physical NIC",
        (Some(_), None) => "direct path OK; system path unreachable",
        (None, _) => "direct probe failed — a VPN driver may be blocking direct sockets",
    };
    format!("{direct}\n{system}\n{verdict}")
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub fn start(name: &str, route: &str, exit: Option<u32>) -> Result<Engine, String> {
    let (ex, note) = resolve_exit(exit)?;

    let path = std::env::temp_dir().join("mirrornic_wintun.dll");
    if std::metadata(&path).map(|m| m.len() != DLL.len() as u64).unwrap_or(true) {
        std::fs::write(&path, DLL).map_err(|e| e.to_string())?;
    }
    let wt = unsafe { wintun::load_from_path(&path) }.map_err(|e| e.to_string())?;
    // Adapter::create already returns Arc<Adapter>
    let adapter = wintun::Adapter::create(&wt, name, "MirrorNIC", None).map_err(|e| e.to_string())?;
    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| e.to_string())?,
    );

    configure(name, route);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>(8192);
    let s2 = session.clone();
    let handle = rt.handle().clone();
    let ex_icmp = ex.clone();
    let thread = std::thread::spawn(move || {
        while let Ok(p) = s2.receive_blocking() {
            let b = p.bytes();
            if b.len() >= 28 && (b[0] >> 4) == 4 && b[9] == 1 {
                let pkt = b.to_vec();
                let s = s2.clone();
                let e = ex_icmp.clone();
                handle.spawn_blocking(move || icmp_forward(pkt, s, e));
                continue;
            }
            if tx.blocking_send(b.to_vec()).is_err() {
                break;
            }
        }
    });

    let s3 = session.clone();
    rt.spawn(run(rx, s3, ex));

    Ok(Engine {
        session,
        thread: Some(thread),
        rt: Some(rt),
        _adapter: adapter,
        _wintun: wt,
        note,
    })
}

async fn run(mut rx: mpsc::Receiver<Vec<u8>>, session: Arc<wintun::Session>, exit: Exit) {
    let (stack, runner, udp, tcp) = match netstack_smoltcp::StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .build()
    {
        Ok(v) => v,
        Err(_) => return,
    };
    let (mut sink, mut stream) = stack.split();

    if let Some(r) = runner {
        tokio::spawn(async move {
            let _ = r.await;
        });
    }
    tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            if sink.send(p).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(Ok(p)) = stream.next().await {
            if let Ok(mut k) = session.allocate_send_packet(p.len() as u16) {
                k.bytes_mut().copy_from_slice(&p);
                session.send_packet(k);
            }
        }
    });
    if let Some(udp) = udp {
        tokio::spawn(udp_loop(udp, exit.clone()));
    }
    if let Some(mut tcp) = tcp {
        while let Some((mut s, _local, remote)) = tcp.next().await {
            let e = exit.clone();
            tokio::spawn(async move {
                if let Ok(Ok(mut o)) =
                    tokio::time::timeout(Duration::from_secs(15), connect_tcp(remote, e)).await
                {
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut o).await;
                }
            });
        }
    }
}

async fn connect_tcp(dst: SocketAddr, exit: Exit) -> std::io::Result<TcpStream> {
    let sock = TcpSocket::new_v4()?;
    // Source-address bind to the physical NIC's own IP (when known) …
    if let Some(ip) = exit.ip {
        let _ = sock.bind(SocketAddr::V4(SocketAddrV4::new(ip, 0)));
    }
    // … and force the outgoing interface regardless of the routing table.
    set_unicast_if(sock.as_raw_socket(), exit.idx);
    let s = sock.connect(dst).await?;
    let _ = s.set_nodelay(true);
    Ok(s)
}

type Reply = (Vec<u8>, SocketAddr, SocketAddr);

async fn udp_loop(udp: netstack_smoltcp::UdpSocket, exit: Exit) {
    let (mut rd, mut wr) = udp.split();
    let (otx, mut orx) = mpsc::unbounded_channel::<Reply>();
    tokio::spawn(async move {
        while let Some(m) = orx.recv().await {
            if wr.send(m).await.is_err() {
                break;
            }
        }
    });
    let mut flows: HashMap<(SocketAddr, SocketAddr), mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
    while let Some((data, src, dst)) = rd.next().await {
        let key = (src, dst);
        let mut data = data;
        if let Some(t) = flows.get(&key) {
            match t.send(data) {
                Ok(_) => continue,
                Err(e) => data = e.0,
            }
        }
        flows.remove(&key);
        if flows.len() > 4096 {
            flows.retain(|_, v| !v.is_closed());
        }
        let (ftx, frx) = mpsc::unbounded_channel();
        let _ = ftx.send(data);
        flows.insert(key, ftx);
        tokio::spawn(udp_flow(frx, otx.clone(), src, dst, exit.clone()));
    }
}

async fn udp_flow(
    mut frx: mpsc::UnboundedReceiver<Vec<u8>>,
    otx: mpsc::UnboundedSender<Reply>,
    src: SocketAddr,
    dst: SocketAddr,
    exit: Exit,
) {
    let std_sock = match exit
        .ip
        .and_then(|ip| std::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(ip, 0))).ok())
    {
        Some(s) => s,
        None => match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return,
        },
    };
    set_unicast_if(std_sock.as_raw_socket(), exit.idx);
    let _ = std_sock.set_nonblocking(true);
    let Ok(sock) = UdpSocket::from_std(std_sock) else { return };
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            m = frx.recv() => match m {
                Some(d) => { let _ = sock.send_to(&d, dst).await; }
                None => break,
            },
            r = sock.recv_from(&mut buf) => {
                if let Ok((n, from)) = r {
                    let _ = otx.send((buf[..n].to_vec(), from, src));
                }
            },
            _ = tokio::time::sleep(Duration::from_secs(60)) => break,
        }
    }
}

fn ip_checksum(h: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in h.chunks(2) {
        let w = if c.len() == 2 { ((c[0] as u32) << 8) | c[1] as u32 } else { (c[0] as u32) << 8 };
        sum += w;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// Forward ICMP echo (ping) through the physical interface and inject the reply.
fn icmp_forward(pkt: Vec<u8>, session: Arc<wintun::Session>, exit: Exit) {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl + 8 || pkt[ihl] != 8 {
        return;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let icmp = &pkt[ihl..];
    let Ok(sock) = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) else { return };
    set_unicast_if(sock.as_raw_socket(), exit.idx);
    if let Some(ip) = exit.ip {
        let _ = sock.bind(&SockAddr::from(SocketAddrV4::new(ip, 0)));
    }
    let _ = sock.set_ttl(pkt[8] as u32);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(800)));
    if sock.send_to(icmp, &SockAddr::from(SocketAddrV4::new(dst, 0))).is_err() {
        return;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
    while std::time::Instant::now() < deadline {
        let n = match sock.recv_from(&mut buf) {
            Ok((n, _)) => n,
            Err(_) => continue,
        };
        let b: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if b.len() < 28 || (b[0] >> 4) != 4 {
            continue;
        }
        let h2 = ((b[0] & 0x0f) as usize) * 4;
        if b.len() < h2 + 8 || b[h2] != 0 || b[h2 + 4..h2 + 8] != icmp[4..8] {
            continue;
        }
        if Ipv4Addr::new(b[12], b[13], b[14], b[15]) != dst {
            continue;
        }
        let payload = &b[h2..];
        let total = 20 + payload.len();
        let mut out = vec![0u8; total];
        out[0] = 0x45;
        out[2] = (total >> 8) as u8;
        out[3] = total as u8;
        out[8] = 64;
        out[9] = 1;
        out[12..16].copy_from_slice(&dst.octets());
        out[16..20].copy_from_slice(&src.octets());
        let c = ip_checksum(&out[..20]);
        out[10] = (c >> 8) as u8;
        out[11] = c as u8;
        out[20..].copy_from_slice(payload);
        if let Ok(mut k) = session.allocate_send_packet(total as u16) {
            k.bytes_mut().copy_from_slice(&out);
            session.send_packet(k);
        }
        return;
    }
}
