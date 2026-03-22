"""
main.py — Entry point for the TCP/IP Packet Analyzer.

NTU EEE TCP/IP Packet Analyzer
--------------------------------
Run with:
    python main.py                          # capture on default interface
    python main.py --iface "Wi-Fi"          # specify interface
    python main.py --filter "tcp port 443"  # only HTTPS traffic
    python main.py --count 200              # stop after 200 packets
    python main.py --timeout 30             # stop after 30 seconds
    python main.py --pcap sample.pcap       # analyse an existing capture file

On Windows, run this script as Administrator (needed for raw socket access).
On Linux/macOS, use: sudo python main.py
"""

import argparse
import sys
from datetime import datetime

from analyzer.sniffer import Sniffer, sniff_from_pcap
from analyzer import plotter


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP/IP Packet Analyzer — NTU EEE Project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--iface",   default=None,  help="Network interface name")
    parser.add_argument("--filter",  default="",    help="BPF filter string")
    parser.add_argument("--count",   type=int, default=100,
                        help="Packets to capture (0 = unlimited, default 100)")
    parser.add_argument("--timeout", type=float, default=None,
                        help="Stop capture after N seconds")
    parser.add_argument("--pcap",    default=None,
                        help="Path to a .pcap file for offline analysis")
    parser.add_argument("--window",  default="1s",
                        help="Throughput resampling window (e.g. 1s, 500ms)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_tag = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # ------------------------------------------------------------------
    # Capture phase
    # ------------------------------------------------------------------
    if args.pcap:
        # Offline mode — read an existing pcap file
        stats = sniff_from_pcap(args.pcap)
    else:
        # Live capture mode
        sniffer = Sniffer(
            iface=args.iface,
            bpf_filter=args.filter,
            count=args.count,
            timeout=args.timeout,
        )
        stats = sniffer.start()

    # ------------------------------------------------------------------
    # Summary statistics
    # ------------------------------------------------------------------
    summary = stats.summary()
    print("\n" + "=" * 50)
    print("  CAPTURE SUMMARY")
    print("=" * 50)
    for key, value in summary.items():
        label = key.replace("_", " ").title()
        print(f"  {label:<30} {value}")
    print("=" * 50)

    if summary["total_packets"] == 0:
        print("\n[main] No packets captured. Exiting.")
        sys.exit(0)

    # ------------------------------------------------------------------
    # Save CSV log
    # ------------------------------------------------------------------
    csv_path = f"logs/packets_{run_tag}.csv"
    stats.save_csv(csv_path)

    # ------------------------------------------------------------------
    # Generate plots
    # ------------------------------------------------------------------
    print("\n[main] Generating plots...")
    plotter.plot_throughput(stats, window=args.window,
                            out_path=f"plots/{run_tag}_throughput.png")
    plotter.plot_protocol_pie(stats,
                              out_path=f"plots/{run_tag}_protocol_dist.png")
    plotter.plot_top_talkers(stats,
                             out_path=f"plots/{run_tag}_top_talkers.png")
    plotter.plot_tcp_flags(stats,
                           out_path=f"plots/{run_tag}_tcp_flags.png")

    print(f"\n[main] Done. Logs → logs/  |  Plots → plots/")


if __name__ == "__main__":
    main()
