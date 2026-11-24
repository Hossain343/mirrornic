use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::windows::io::AsRawSocket;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

static DLL: &[u8] = include_bytes!("../assets/wintun.dll");

pub struct Engine {
    session: Arc<wintun::Session>,
    thread: Option<std::thread::JoinHandle<()>>,
    rt: Option<Runtime>,
    _adapter: Arc<wintun::Adapter>,
    _wintun: wintun::Wintun,
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
    netsh(&["interface", "ipv4", "set", "interface", &i, "metric=1"]);
    netsh(&["interface", "ipv4", "set", "subinterface", name, "mtu=1500", "store=active"]);
    for r in route.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let p = format!("prefix={}", r);
        netsh(&["interface", "ipv4", "add", "route", &p, &i, "nexthop=0.0.0.0", "metric=1", "store=active"]);
    }
    netsh(&["interface", "ip", "set", "dns", &n, "static", "1.1.1.1", "validate=no"]);
    netsh(&["interface", "ip", "add", "dns", &n, "8.8.8.8", "index=2", "validate=no"]);
}

pub fn list_ifaces() -> Vec<(u32, String)> {
    let mut v = Vec::new();
    if let Ok(o) = Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .creation_flags(0x0800_0000)
        .output()
    {
        let text = String::from_utf8_lossy(&o.stdout).to_string();
        for line in text.lines() {
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.len() >= 5 {
                if let Ok(i) = t[0].parse::<u32>() {
                    let nm = t[4..].join(" ");
                    if !nm.contains("Loopback") {
                        v.push((i, nm));
                    }
                }
            }
        }
    }
    v
}

fn best_if() -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface;
    let ip = u32::from_ne_bytes([8, 8, 8, 8]);
    let mut i = 0u32;
    if unsafe { GetBestInterface(ip, &mut i) } == 0 {
        Some(i)
    } else {
        None
    }
}

// Force a socket out of the physical interface (prevents routing loop).
fn set_unicast_if(raw: u64, idx: u32) {
    use windows_sys::Win32::Networking::WinSock::setsockopt;
    let v = idx.to_be();
    unsafe {
        setsockopt(raw as usize, 0, 31, &v as *const u32 as *const u8, 4);
    }
}

pub fn start(name: &str, route: &str, exit: Option<u32>) -> Result<Engine, String> {
    let idx = match exit {
        Some(i) => i,
        None => best_if().ok_or_else(|| "no internet".to_string())?,
    };

    let path = std::env::temp_dir().join("mirrornic_wintun.dll");
    if std::fs::metadata(&path).map(|m| m.len() != DLL.len() as u64).unwrap_or(true) {
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
    let thread = std::thread::spawn(move || {
        while let Ok(p) = s2.receive_blocking() {
            let b = p.bytes();
            if b.len() >= 28 && (b[0] >> 4) == 4 && b[9] == 1 {
                let pkt = b.to_vec();
                let s = s2.clone();
                handle.spawn_blocking(move || icmp_forward(pkt, s, idx));
                continue;
            }
            if tx.blocking_send(b.to_vec()).is_err() {
                break;
            }
        }
    });

    let s3 = session.clone();
    rt.spawn(run(rx, s3, idx));

    Ok(Engine {
        session,
        thread: Some(thread),
        rt: Some(rt),
        _adapter: adapter,
        _wintun: wt,
    })
}

async fn run(mut rx: mpsc::Receiver<Vec<u8>>, session: Arc<wintun::Session>, idx: u32) {
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
        tokio::spawn(udp_loop(udp, idx));
    }
    if let Some(mut tcp) = tcp {
        while let Some((mut s, _local, remote)) = tcp.next().await {
            tokio::spawn(async move {
                if let Ok(Ok(mut o)) =
                    tokio::time::timeout(Duration::from_secs(15), connect_tcp(remote, idx)).await
                {
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut o).await;
                }
            });
        }
    }
}

async fn connect_tcp(dst: SocketAddr, idx: u32) -> std::io::Result<TcpStream> {
    let sock = TcpSocket::new_v4()?;
    set_unicast_if(sock.as_raw_socket(), idx);
    let s = sock.connect(dst).await?;
    let _ = s.set_nodelay(true);
    Ok(s)
}

type Reply = (Vec<u8>, SocketAddr, SocketAddr);

async fn udp_loop(udp: netstack_smoltcp::UdpSocket, idx: u32) {
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
        tokio::spawn(udp_flow(frx, otx.clone(), src, dst, idx));
    }
}

async fn udp_flow(
    mut frx: mpsc::UnboundedReceiver<Vec<u8>>,
    otx: mpsc::UnboundedSender<Reply>,
    src: SocketAddr,
    dst: SocketAddr,
    idx: u32,
) {
    let Ok(std_sock) = std::net::UdpSocket::bind("0.0.0.0:0") else { return };
    set_unicast_if(std_sock.as_raw_socket(), idx);
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
fn icmp_forward(pkt: Vec<u8>, session: Arc<wintun::Session>, idx: u32) {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl + 8 || pkt[ihl] != 8 {
        return;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let icmp = &pkt[ihl..];
    let Ok(sock) = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) else { return };
    set_unicast_if(sock.as_raw_socket(), idx);
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
