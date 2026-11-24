# MirrorNIC

**Virtual network adapter for Windows that routes selected traffic through a real physical interface — clean, lightweight, and under your control.**

MirrorNIC creates a Wintun-based virtual NIC, assigns it an IP, installs routes you choose, and transparently forwards TCP / UDP / ICMP through a userspace netstack while forcing outbound sockets onto a specific physical interface. Ideal for multi-WAN setups, testing, traffic isolation, and "send this traffic out that NIC" scenarios.

---

## What it does (in plain words)

1. Creates a virtual adapter named by you (default `MirrorNIC`) using [Wintun](https://www.wintun.net).
2. Configures it with IP `10.66.0.2/24`, low metric, DNS, and the routes you specify.
3. Captures packets arriving on the virtual adapter.
4. Handles them with a userspace TCP/UDP stack ([netstack-smoltcp](https://github.com/automesh-network/netstack-smoltcp)).
5. Opens real sockets on the **physical exit interface** you chose (or auto-detected) and relays the traffic.
6. Injects replies back into the virtual adapter so apps talking to MirrorNIC see a normal network path.

ICMP echo (ping) is forwarded with a dedicated path so connectivity checks work.

---

## Features

| Feature | Detail |
|--------|--------|
| Virtual NIC | Wintun driver, no NDIS intermediate driver required |
| Selective routing | Comma-separated prefixes (e.g. `0.0.0.0/0` or `1.2.3.0/24,8.8.8.8/32`) |
| Exit interface | Auto (best route to 8.8.8.8) or pick any interface by index |
| TCP / UDP / ICMP | Full relay through userspace stack + forced interface binding |
| Small GUI | egui/eframe — ON/OFF, name, routes, exit NIC, public IP test |
| Admin-aware | Uses elevated `netsh` under the hood; run as Administrator |
| Release-optimized | LTO, strip, `panic=abort` for a compact binary |

---

## Project structure

```
mirrornic/
├── .github/workflows/build.yml   # Windows CI: download wintun.dll → cargo build --release → artifact
├── assets/
│   ├── README.txt                # Where to put wintun.dll for local builds
│   └── wintun.dll                # (CI places it here; not committed)
├── src/
│   ├── main.rs                   # egui app: UI, config, start/stop engine
│   └── engine.rs                 # Wintun session, netsh, netstack, TCP/UDP/ICMP relay
├── build.rs                      # Embeds Windows manifest (admin / DPI)
├── app.manifest / app.rc         # Application manifest resources
├── Cargo.toml
└── README.md                     # You are here
```

### Key modules

- **`main.rs`** — Desktop UI (ON/OFF button, adapter name, route list, exit interface combo, public-IP test). Starts the engine on a background thread and shows status.
- **`engine.rs`** — Core:
  - Load Wintun DLL, create adapter + session
  - `netsh` configuration (IP, metric, routes, DNS)
  - Packet receive thread → channel into async runtime
  - `netstack-smoltcp` Stack for TCP/UDP
  - Per-flow UDP NAT, TCP bidirectional copy, ICMP echo forwarder
  - `IP_UNICAST_IF` (setsockopt) so real sockets leave via the chosen physical interface

---

## Requirements

- **Windows** (x64)
- **Administrator** privileges (adapter creation + routing)
- [Rust](https://rustup.rs) stable (for building)
- `wintun.dll` (amd64) from [wintun.net](https://www.wintun.net) — CI downloads it automatically; for local builds put it in `assets/wintun.dll`

---

## Build

```bash
# Place wintun.dll in assets/ first (or let CI do it)
cargo build --release
# Binary: target/release/mirrornic.exe
```

GitHub Actions workflow `build-windows` produces a downloadable artifact named `mirrornic` on every push.

---

## Usage

1. Run `mirrornic.exe` **as Administrator**.
2. Optionally change **Adapter name** and **Route** (comma-separated prefixes).
3. Choose **Exit interface** (Auto or a specific NIC) → Refresh if needed.
4. Click **ON**. The virtual adapter appears; routes are installed.
5. Use **Test** to fetch your public IP (via the current path) as a quick sanity check.
6. Click **OFF** or close the app to tear down the session and clean up.

---

## Use cases & why it’s useful

| Scenario | How MirrorNIC helps |
|----------|---------------------|
| **Multi-WAN / dual ISP** | Force a subset of traffic (or everything) out a secondary modem/NIC without changing the system default route for all apps. |
| **Per-app or per-prefix isolation** | Point specific destinations at the virtual adapter’s routes and control the physical exit. |
| **Lab & testing** | Create a disposable virtual path with known IP/DNS and inspect or shape traffic before it hits the real wire. |
| **Avoid routing loops** | Explicit `IP_UNICAST_IF` binding prevents packets from re-entering the virtual adapter. |
| **Lightweight alternative to full VPN/TUN stacks** | No heavy control plane — just a virtual NIC + userspace forwarder. |
| **ICMP-aware** | Ping works, so monitoring and traceroute-style checks remain usable. |

### Strengths

- Small surface area, readable Rust codebase.
- Uses battle-tested Wintun + smoltcp-based netstack.
- Release profile is aggressive (LTO + strip) for a compact exee.
- GUI is minimal but sufficient for day-to-day control.

### Limitations (honest)

- Windows-only.
- Requires Administrator.
- Not a full VPN (no encryption, no remote peer) — it is a **local policy / interface steering** tool.
- Very large numbers of concurrent short-lived UDP flows may need tuning of the in-memory flow map.

---

## Technical notes

- Virtual IP: `10.66.0.2/24` (hardcoded in `configure`).
- DNS set to `1.1.1.1` and `8.8.8.8` on the virtual interface.
- Outbound sockets are bound to the chosen interface index via `IP_UNICAST_IF` (level `IPPROTO_IP`, optname `31`).
- TCP connections get a 15s connect timeout; UDP flows idle-timeout after 60s.
- ICMP echo-request is rewritten and answered by a small blocking helper so the virtual path stays pingable.

---

## License / credit

- Wintun is © WireGuard / Jason A. Donenfeld — obtain the signed driver from the official site.
- Built with Rust, egui/eframe, tokio, netstack-smoltcp, wintun crate, windows-sys.

---

**MirrorNIC** — give selected traffic a clean, intentional way out.
