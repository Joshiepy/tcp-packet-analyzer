TCP/IP Packet Analyzer
EEE Year 2 — Computer Networks Project

A Python tool that captures live network traffic (or reads `.pcap` files),
decodes Ethernet / IP / TCP / UDP headers layer-by-layer, logs statistics
to a pandas DataFrame, and produces matplotlib plots.

---

## Folder structure

```
Proj1_TCP/
├── analyzer/
│   ├── __init__.py
│   ├── decoder.py      # Layer-by-layer header parsing
│   ├── sniffer.py      # Scapy-based live capture & pcap reader
│   ├── stats.py        # Pandas accumulator + throughput resampling
│   └── plotter.py      # Matplotlib charts (throughput, pie, bars)
├── logs/               # CSV packet logs (created at runtime)
├── plots/              # PNG charts (created at runtime)
├── main.py             # CLI entry point
├── requirements.txt
└── README.md
```

---

## Prerequisites

| Requirement | Why |
|---|---|
| Python 3.11+ | Uses `X \| Y` type union syntax |
| [Npcap](https://npcap.com/) (Windows) | Raw socket driver for Scapy |
| Administrator / root privileges | Required for promiscuous-mode capture |

Install Python dependencies:
```bash
pip install -r requirements.txt
```

---

## Quick start

### Live capture (Windows — run cmd.exe as Administrator)
```bash
# Capture 100 packets on the default interface
python main.py

# Capture on Wi-Fi, filter to HTTPS only, stop after 30 s
python main.py --iface "Wi-Fi" --filter "tcp port 443" --timeout 30

# Unlimited capture on Ethernet until Ctrl-C
python main.py --iface "Ethernet" --count 0
```

### Offline analysis (pcap file)
```bash
python main.py --pcap sample.pcap
```

### Available flags
| Flag | Default | Description |
|---|---|---|
| `--iface` | system default | NIC name (e.g. `"Wi-Fi"`, `"eth0"`) |
| `--filter` | _(none)_ | BPF filter string |
| `--count` | `100` | Packets before stopping (`0` = unlimited) |
| `--timeout` | _(none)_ | Seconds before auto-stop |
| `--pcap` | _(none)_ | Path to `.pcap` / `.pcapng` for offline mode |
| `--window` | `1s` | Throughput resampling window (`500ms`, `2s`, …) |

---

## How it works — Layer by layer

### The TCP/IP stack (bottom → top)

```
┌─────────────────────────────────────────────┐
│  Application (HTTP, DNS, TLS …)             │  data
├─────────────────────────────────────────────┤
│  Transport    TCP / UDP                     │  ports, flow control
├─────────────────────────────────────────────┤
│  Network      IPv4                          │  routing, TTL
├─────────────────────────────────────────────┤
│  Data Link    Ethernet (802.3)              │  MAC addresses
└─────────────────────────────────────────────┘
```

Scapy represents this stack as chained Python objects:
```python
pkt[Ether] / pkt[IP] / pkt[TCP] / pkt[Raw]
```

### decoder.py
Extracts header fields from each layer into a flat Python dict:

| Layer | Key fields extracted |
|---|---|
| Ethernet | `eth_src`, `eth_dst`, `eth_type` |
| IP | `ip_src`, `ip_dst`, `ip_proto`, `ip_ttl`, `ip_len`, `ip_tos` |
| TCP | `tcp_sport`, `tcp_dport`, `tcp_seq`, `tcp_ack`, `tcp_flags`, `tcp_window` |
| UDP | `udp_sport`, `udp_dport`, `udp_len` |

### stats.py
Each packet dict becomes a row in a **pandas DataFrame**.

- `throughput_series(window)` — resamples `ip_len` (bytes) into equal time buckets using `df.resample()`, equivalent to a rectangular integration window
- `top_talkers(n)` — `groupby('ip_src')['ip_len'].sum()` ranks IPs by traffic volume
- `save_csv(path)` — persists the full log for offline processing

### plotter.py
Four charts saved as PNG files under `plots/`:

| File | What it shows |
|---|---|
| `*_throughput.png` | Bytes/window over time (line + fill) |
| `*_protocol_dist.png` | TCP vs UDP packet count (pie) |
| `*_top_talkers.png` | Top-5 source IPs by bytes (horizontal bar) |
| `*_tcp_flags.png` | TCP flag combinations seen (bar) — useful for spotting SYN floods |

---

## Understanding BPF filters

BPF (Berkeley Packet Filter) runs *inside the kernel* so only matching
packets are passed to Python — very efficient.

```bash
tcp                        # TCP only
udp                        # UDP only
tcp port 80                # HTTP
tcp port 443               # HTTPS / TLS
udp port 53                # DNS
host 192.168.1.1           # to/from a specific host
src host 10.0.0.5          # from a specific source
not arp                    # exclude ARP
tcp and not port 22        # TCP but not SSH
```

---

## TCP flag cheat sheet

| Flags | Meaning |
|---|---|
| `S` | SYN — connection request |
| `SA` | SYN-ACK — server accepting (3-way handshake) |
| `A` | ACK — acknowledgement |
| `PA` | PSH-ACK — data push (most HTTP/TLS records) |
| `FA` | FIN-ACK — graceful teardown |
| `R` | RST — abrupt reset (closed port, firewall drop) |

Many bare `S` flags with no `SA` response → possible SYN flood / port scan.

---

## Sample output

```
[sniffer] Starting capture on Wi-Fi
          filter="tcp port 443" | count=100 | no timeout

  [TCP]  192.168.1.5:54321 → 142.250.185.46:443  flags=PA  len=1440B
  [TCP]  142.250.185.46:443 → 192.168.1.5:54321  flags=A   len=52B
  ...

==================================================
  CAPTURE SUMMARY
==================================================
  Total Packets                  100
  Elapsed S                      4.23
  Total Bytes                    98432
  Avg Throughput Bps             186155.1
  Tcp Packets                    98
  Udp Packets                    2
  Unique Src Ips                 6
  Unique Dst Ips                 4
==================================================

[stats]   Saved 100 rows → logs/packets_20260323_120000.csv
[plotter] Saved → plots/20260323_120000_throughput.png
[plotter] Saved → plots/20260323_120000_protocol_dist.png
[plotter] Saved → plots/20260323_120000_top_talkers.png
[plotter] Saved → plots/20260323_120000_tcp_flags.png
```

---

## Extending the project

Ideas for further development:
- **RTT estimation** — correlate TCP SYN and SYN-ACK timestamps
- **HTTP dissection** — parse `Raw` payload for GET/POST verb and Host header
- **Geo-IP mapping** — use `geoip2` library to map IPs to countries
- **Real-time dashboard** — replace matplotlib with `dash` or `streamlit`
- **Anomaly detection** — flag IPs with unusually high packet rates using a rolling z-score

---

*Built with [Scapy](https://scapy.net/), [pandas](https://pandas.pydata.org/),
and [matplotlib](https://matplotlib.org/).*
