"""
plotter.py — Matplotlib visualisations for captured traffic.

NTU EEE TCP/IP Packet Analyzer
--------------------------------
Three plots are produced:
  1. Throughput over time  — bytes/s resampled from ip_len
  2. Protocol distribution — pie chart of TCP vs UDP vs Other
  3. Top-talker bar chart  — top-5 source IPs by total bytes

matplotlib.pyplot is the MATLAB-style stateful API. Each `plt.figure()`
call creates an isolated canvas so we can save multiple independent PNGs
without one plot's data leaking into the next.
"""

import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd

from .stats import PacketStats


# -----------------------------------------------------------------------
# 1. Throughput over time
# -----------------------------------------------------------------------

def plot_throughput(stats: PacketStats, window: str = "1s",
                    out_path: str = "plots/throughput.png") -> None:
    """
    Line plot of bytes transferred per time window.

    Why bytes/s and not packets/s?
      Bytes/s (throughput) maps directly to link utilisation. A flood of
      tiny ACKs shows up as high packets/s but low throughput; a single
      large file transfer shows the reverse. Both metrics matter, but
      throughput is the one engineers report to network stakeholders.

    The x-axis uses mdates.AutoDateFormatter so the labels automatically
    switch between HH:MM:SS and HH:MM depending on capture duration.
    """
    series = stats.throughput_series(window)
    if series.empty:
        print("[plotter] No data for throughput plot.")
        return

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(series.index.to_pydatetime(), series.values,
            linewidth=1.2, color="#1f77b4")
    ax.fill_between(series.index.to_pydatetime(), series.values,
                    alpha=0.25, color="#1f77b4")

    ax.xaxis.set_major_formatter(mdates.AutoDateFormatter(mdates.AutoDateLocator()))
    fig.autofmt_xdate()

    ax.set_title(f"Network Throughput (window = {window})", fontsize=13)
    ax.set_xlabel("Time (UTC)")
    ax.set_ylabel("Bytes / window")
    ax.grid(True, linestyle="--", alpha=0.5)

    _save(fig, out_path)


# -----------------------------------------------------------------------
# 2. Protocol distribution pie chart
# -----------------------------------------------------------------------

def plot_protocol_pie(stats: PacketStats,
                      out_path: str = "plots/protocol_dist.png") -> None:
    """
    Pie chart of packet counts by transport protocol.

    `autopct='%1.1f%%'` formats slice labels as percentages with one
    decimal place — e.g., "73.4%". The `startangle=140` rotates the
    first slice so TCP (typically the largest) starts near the top.
    """
    counts = stats.protocol_counts()
    if counts.empty:
        print("[plotter] No data for protocol pie chart.")
        return

    labels = counts.index.fillna("Other").tolist()
    values = counts.values

    fig, ax = plt.subplots(figsize=(6, 6))
    wedge_props = {"edgecolor": "white", "linewidth": 1.5}
    ax.pie(values, labels=labels, autopct="%1.1f%%",
           startangle=140, wedgeprops=wedge_props,
           colors=["#1f77b4", "#ff7f0e", "#2ca02c"])
    ax.set_title("Transport Protocol Distribution", fontsize=13)

    _save(fig, out_path)


# -----------------------------------------------------------------------
# 3. Top-talker bar chart
# -----------------------------------------------------------------------

def plot_top_talkers(stats: PacketStats, n: int = 5,
                     out_path: str = "plots/top_talkers.png") -> None:
    """
    Horizontal bar chart of the top-N source IPs by bytes sent.

    Horizontal orientation is preferred over vertical when labels (IP
    addresses) are long strings — it avoids 45° rotation and keeps the
    chart readable.
    """
    df = stats.top_talkers(n)
    if df.empty:
        print("[plotter] No data for top-talker chart.")
        return

    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.barh(df["ip_src"], df["bytes_sent"], color="#2ca02c")
    ax.bar_label(bars, fmt="%d B", padding=4, fontsize=9)
    ax.invert_yaxis()  # largest bar at top
    ax.set_title(f"Top {n} Source IPs by Bytes Sent", fontsize=13)
    ax.set_xlabel("Total Bytes")
    ax.set_ylabel("Source IP")
    ax.grid(True, axis="x", linestyle="--", alpha=0.5)

    _save(fig, out_path)


# -----------------------------------------------------------------------
# 4. TCP flags distribution (bonus — useful for spotting SYN floods)
# -----------------------------------------------------------------------

def plot_tcp_flags(stats: PacketStats,
                   out_path: str = "plots/tcp_flags.png") -> None:
    """
    Bar chart of TCP flag combinations seen in the capture.

    Common flag combos and what they mean:
      S  (SYN)       — connection initiation
      SA (SYN-ACK)   — server accepting connection (3-way handshake reply)
      A  (ACK)       — data acknowledgement
      PA (PSH-ACK)   — data push (most HTTP/TLS records)
      FA (FIN-ACK)   — graceful connection teardown
      R  (RST)       — abrupt connection reset (port closed / firewall)

    A capture full of bare SYN packets with no SYN-ACK suggests a
    SYN-flood DoS attack or a port scan (e.g., nmap -sS).
    """
    df = stats.to_dataframe()
    if df.empty or "tcp_flags" not in df.columns:
        print("[plotter] No TCP data for flags chart.")
        return

    flag_counts = df["tcp_flags"].dropna().value_counts().head(10)

    fig, ax = plt.subplots(figsize=(9, 4))
    flag_counts.plot(kind="bar", ax=ax, color="#d62728")
    ax.set_title("TCP Flag Distribution (top 10)", fontsize=13)
    ax.set_xlabel("Flag Combination")
    ax.set_ylabel("Packet Count")
    ax.tick_params(axis="x", rotation=30)
    ax.grid(True, axis="y", linestyle="--", alpha=0.5)

    _save(fig, out_path)


# -----------------------------------------------------------------------
# Helper
# -----------------------------------------------------------------------

def _save(fig: plt.Figure, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[plotter] Saved → {path}")


def plot_all(stats: PacketStats) -> None:
    """Convenience wrapper — generate every chart in one call."""
    plot_throughput(stats)
    plot_protocol_pie(stats)
    plot_top_talkers(stats)
    plot_tcp_flags(stats)
