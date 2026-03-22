"""
decoder.py — Layer-by-layer packet decoder.

NTU EEE TCP/IP Packet Analyzer
--------------------------------
The TCP/IP stack is built in layers. Scapy models each layer as a Python
object chained together with the `/` operator (or accessed via `.payload`).

Layer order (bottom → top):
  Ethernet (L2) → IP (L3) → TCP or UDP (L4) → Raw payload

We check for each layer's presence before accessing its fields to avoid
crashes on packets that don't carry every layer (e.g., ARP has no IP).
"""

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet


def decode_ethernet(pkt: Packet) -> dict:
    """
    Ethernet frame header (IEEE 802.3)
    - src / dst : 48-bit MAC addresses (xx:xx:xx:xx:xx:xx)
    - type      : EtherType — 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6
    """
    if Ether not in pkt:
        return {}
    eth = pkt[Ether]
    return {
        "eth_src": eth.src,
        "eth_dst": eth.dst,
        "eth_type": hex(eth.type),
    }


def decode_ip(pkt: Packet) -> dict:
    """
    IPv4 header (RFC 791)
    - src / dst : 32-bit IP addresses in dotted-decimal
    - proto     : 6 = TCP, 17 = UDP, 1 = ICMP
    - ttl       : Time-To-Live — decremented at each hop; prevents loops
    - len       : Total IP datagram length in bytes (header + payload)
    - tos       : Type of Service / DSCP — used for QoS prioritisation
    """
    if IP not in pkt:
        return {}
    ip = pkt[IP]
    return {
        "ip_src": ip.src,
        "ip_dst": ip.dst,
        "ip_proto": ip.proto,
        "ip_ttl": ip.ttl,
        "ip_len": ip.len,
        "ip_tos": ip.tos,
    }


def decode_tcp(pkt: Packet) -> dict:
    """
    TCP header (RFC 793)
    - sport / dport : 16-bit port numbers (identifies the application)
    - seq / ack     : 32-bit sequence and acknowledgement numbers
    - flags         : Control bits — S(SYN), A(ACK), F(FIN), R(RST), P(PSH)
    - window        : Receive window size for flow control
    - payload_len   : Number of application-data bytes carried
    """
    if TCP not in pkt:
        return {}
    tcp = pkt[TCP]
    return {
        "tcp_sport": tcp.sport,
        "tcp_dport": tcp.dport,
        "tcp_seq": tcp.seq,
        "tcp_ack": tcp.ack,
        "tcp_flags": str(tcp.flags),
        "tcp_window": tcp.window,
        "tcp_payload_len": len(tcp.payload),
    }


def decode_udp(pkt: Packet) -> dict:
    """
    UDP header (RFC 768)
    - sport / dport : 16-bit port numbers
    - len           : UDP datagram length (header 8 B + payload)
    UDP is connectionless — no handshake, no reliability guarantees.
    Common uses: DNS (53), DHCP (67/68), RTP media streams.
    """
    if UDP not in pkt:
        return {}
    udp = pkt[UDP]
    return {
        "udp_sport": udp.sport,
        "udp_dport": udp.dport,
        "udp_len": udp.len,
        "udp_payload_len": len(udp.payload),
    }


def decode_packet(pkt: Packet, timestamp: float) -> dict:
    """
    Combines all layer decoders into one flat record per packet.
    `timestamp` comes from Scapy's sniff callback (Unix epoch, float).
    The `transport` field lets downstream code quickly filter TCP vs UDP.
    """
    record = {"timestamp": timestamp, "transport": None}

    record.update(decode_ethernet(pkt))
    record.update(decode_ip(pkt))

    if TCP in pkt:
        record["transport"] = "TCP"
        record.update(decode_tcp(pkt))
    elif UDP in pkt:
        record["transport"] = "UDP"
        record.update(decode_udp(pkt))

    return record
