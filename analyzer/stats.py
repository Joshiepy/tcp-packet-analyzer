"""
stats.py — Pandas-based packet statistics logger.

NTU EEE TCP/IP Packet Analyzer
--------------------------------
Each packet becomes one row in a pandas DataFrame — analogous to a row
in a database table. This lets us use pandas' powerful aggregation and
time-series resampling to compute throughput, protocol distribution, etc.

Key pandas concepts used here:
  - pd.DataFrame       : 2D table of typed columns
  - pd.to_datetime     : converts Unix timestamps to DatetimeIndex
  - resample('1s')     : groups rows by 1-second time windows (like a
                         sliding window average in DSP)
  - groupby / value_counts : SQL-style GROUP BY for protocol counts
"""

import os
import pandas as pd


class PacketStats:
    def __init__(self):
        # List of dicts; each dict is one decoded packet record.
        # We defer DataFrame construction until we need to query,
        # because appending to a list is O(1) while appending to a
        # DataFrame is O(n) (it copies the whole frame each time).
        self._records: list[dict] = []

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def add(self, record: dict) -> None:
        """Append one decoded packet record."""
        self._records.append(record)

    # ------------------------------------------------------------------
    # DataFrame access
    # ------------------------------------------------------------------

    def to_dataframe(self) -> pd.DataFrame:
        """
        Convert accumulated records to a DataFrame with a DatetimeIndex.
        The index is UTC time derived from the Unix epoch float that
        Scapy stamps on every captured packet.
        """
        if not self._records:
            return pd.DataFrame()
        df = pd.DataFrame(self._records)
        df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s", utc=True)
        df = df.set_index("timestamp").sort_index()
        return df

    # ------------------------------------------------------------------
    # Summary statistics
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """
        Returns a dict of high-level stats suitable for console printing.
        ip_len is the IPv4 datagram length in bytes — summing it gives
        total bytes transferred; dividing by elapsed seconds gives
        average throughput in bytes/s.
        """
        df = self.to_dataframe()
        if df.empty:
            return {"total_packets": 0}

        elapsed = (df.index[-1] - df.index[0]).total_seconds() or 1.0
        total_bytes = df["ip_len"].sum() if "ip_len" in df.columns else 0

        return {
            "total_packets": len(df),
            "elapsed_s": round(elapsed, 2),
            "total_bytes": int(total_bytes),
            "avg_throughput_bps": round(total_bytes * 8 / elapsed, 1),
            "tcp_packets": int(df["transport"].eq("TCP").sum()),
            "udp_packets": int(df["transport"].eq("UDP").sum()),
            "unique_src_ips": df["ip_src"].nunique() if "ip_src" in df.columns else 0,
            "unique_dst_ips": df["ip_dst"].nunique() if "ip_dst" in df.columns else 0,
        }

    def throughput_series(self, window: str = "1s") -> pd.Series:
        """
        Resample packet bytes into equal time windows.

        `window` uses pandas offset aliases: '1s' = 1 second,
        '500ms' = half-second, '5s' = 5 seconds, etc.

        How resampling works:
          - The DatetimeIndex is divided into fixed-width bins.
          - ip_len values falling in each bin are summed → bytes/window.
          - This is conceptually identical to a rectangular window
            integration in DSP.
        """
        df = self.to_dataframe()
        if df.empty or "ip_len" not in df.columns:
            return pd.Series(dtype=float)
        return df["ip_len"].resample(window).sum().fillna(0)

    def protocol_counts(self) -> pd.Series:
        """Count packets grouped by transport protocol (TCP / UDP / None)."""
        df = self.to_dataframe()
        if df.empty or "transport" not in df.columns:
            return pd.Series(dtype=int)
        return df["transport"].value_counts()

    def top_talkers(self, n: int = 5) -> pd.DataFrame:
        """
        Return the top-N source IPs ranked by total bytes sent.
        Useful for spotting dominant flows or potential DoS sources.
        """
        df = self.to_dataframe()
        if df.empty or "ip_src" not in df.columns:
            return pd.DataFrame()
        return (
            df.groupby("ip_src")["ip_len"]
            .sum()
            .sort_values(ascending=False)
            .head(n)
            .rename("bytes_sent")
            .reset_index()
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_csv(self, path: str = "logs/packets.csv") -> None:
        """
        Persist the full packet log to CSV.
        CSV is plain text — readable in Excel, grep-able, and easy to
        reload with pd.read_csv() for offline analysis.
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        df = self.to_dataframe()
        if not df.empty:
            df.to_csv(path)
            print(f"[stats] Saved {len(df)} rows → {path}")
