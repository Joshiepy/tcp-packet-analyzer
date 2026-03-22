"""
sniffer.py — Live packet capture engine using Scapy.

NTU EEE TCP/IP Packet Analyzer
--------------------------------
Scapy's sniff() function puts the NIC into promiscuous mode and calls
our callback for each packet that passes the BPF filter.

BPF (Berkeley Packet Filter) is a mini-language compiled to bytecode
that runs inside the kernel, so packets that don't match are dropped
*before* they reach Python — this is much more efficient than filtering
in userspace. Examples:
  "tcp"            → only TCP packets
  "udp port 53"   → only DNS queries/responses
  "host 8.8.8.8"  → packets to/from a specific IP
  ""               → capture everything (default here)

On Windows, Scapy uses Npcap instead of libpcap. Make sure Npcap is
installed (https://npcap.com/) and run this script as Administrator.
On Linux/macOS, run as root or with `CAP_NET_RAW` capability.
"""

import time
from scapy.all import sniff
from scapy.packet import Packet

from .decoder import decode_packet
from .stats import PacketStats


class Sniffer:
    def __init__(
        self,
        iface: str | None = None,
        bpf_filter: str = "",
        count: int = 0,
        timeout: float | None = None,
    ):
        """
        Parameters
        ----------
        iface      : Network interface name (e.g. "Ethernet", "Wi-Fi", "eth0").
                     None → Scapy picks the default interface.
        bpf_filter : BPF filter string. Empty string = capture all traffic.
        count      : Stop after this many packets. 0 = unlimited.
        timeout    : Stop after this many seconds. None = run until Ctrl-C.
        """
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.count = count
        self.timeout = timeout
        self.stats = PacketStats()
        self._pkt_count = 0

    # ------------------------------------------------------------------
    # Packet callback — called by Scapy for every captured packet
    # ------------------------------------------------------------------

    def _process(self, pkt: Packet) -> None:
        """
        This function runs once per packet.

        Scapy passes the raw packet object. We:
          1. Stamp it with the current Unix time (Scapy's internal
             timestamp is also available as pkt.time, which we use).
          2. Decode all layers into a flat dict.
          3. Store the dict in PacketStats.
          4. Print a one-liner summary to stdout.

        Keep this function fast — it runs in the capture thread.
        """
        ts = float(pkt.time)  # Unix epoch float (e.g. 1711000000.123456)
        record = decode_packet(pkt, ts)
        self.stats.add(record)
        self._pkt_count += 1
        self._print_line(record)

    # ------------------------------------------------------------------
    # Pretty-print one packet to stdout
    # ------------------------------------------------------------------

    @staticmethod
    def _print_line(record: dict) -> None:
        proto = record.get("transport", "?")
        src = record.get("ip_src", record.get("eth_src", "?"))
        dst = record.get("ip_dst", record.get("eth_dst", "?"))
        length = record.get("ip_len", 0)

        if proto == "TCP":
            sport = record.get("tcp_sport", "?")
            dport = record.get("tcp_dport", "?")
            flags = record.get("tcp_flags", "")
            print(f"  [TCP]  {src}:{sport} → {dst}:{dport}  "
                  f"flags={flags}  len={length}B")
        elif proto == "UDP":
            sport = record.get("udp_sport", "?")
            dport = record.get("udp_dport", "?")
            print(f"  [UDP]  {src}:{sport} → {dst}:{dport}  len={length}B")
        else:
            eth_type = record.get("eth_type", "?")
            print(f"  [L2]   {src} → {dst}  EtherType={eth_type}  len={length}B")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> PacketStats:
        """
        Begin capture. Blocks until count or timeout is reached, or the
        user presses Ctrl-C.

        Returns the PacketStats object so the caller can generate plots
        and save CSVs after capture ends.
        """
        iface_msg = self.iface or "default interface"
        filter_msg = f'filter="{self.bpf_filter}"' if self.bpf_filter else "no filter"
        count_msg = f"count={self.count}" if self.count else "unlimited"
        timeout_msg = f"timeout={self.timeout}s" if self.timeout else "no timeout"

        print(f"\n[sniffer] Starting capture on {iface_msg}")
        print(f"          {filter_msg} | {count_msg} | {timeout_msg}")
        print(f"          Press Ctrl-C to stop early.\n")

        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self._process,
                count=self.count,
                timeout=self.timeout,
                store=False,   # don't buffer all packets in RAM
            )
        except KeyboardInterrupt:
            print("\n[sniffer] Interrupted by user.")

        print(f"\n[sniffer] Capture complete — {self._pkt_count} packets.")
        return self.stats


def sniff_from_pcap(path: str) -> PacketStats:
    """
    Offline analysis: read a pre-recorded .pcap / .pcapng file instead of
    capturing live traffic. Useful for lab assignments where you're given
    a sample trace (e.g., from Wireshark).

    Usage:
        from analyzer.sniffer import sniff_from_pcap
        stats = sniff_from_pcap("sample.pcap")
    """
    from scapy.utils import rdpcap

    print(f"[sniffer] Reading pcap: {path}")
    pkts = rdpcap(path)
    stats = PacketStats()
    for pkt in pkts:
        ts = float(pkt.time)
        record = decode_packet(pkt, ts)
        stats.add(record)
    print(f"[sniffer] Loaded {len(pkts)} packets from {path}")
    return stats
