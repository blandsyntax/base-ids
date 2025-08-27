#!/usr/bin/env python3

from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, ARP, DNS, wrpcap
import time
import os
import requests
import re
import numpy as np
from collections import defaultdict
from typing import Optional, Dict, List, Tuple

# manual configs here homie
BLACKLIST_IPS: List[str] = ["192.168.1.100", "10.0.0.200"]
DISCORD_WEBHOOK_URL: str = "https://discord.com/api/webhooks/your_webhook_here"

# threshold config
SYN_THRESHOLD: int = 50
SYN_WINDOW_SIZE: int = 60
DDoS_THRESHOLD: int = 100
PORT_SCAN_THRESHOLD: int = 5
SCAN_WINDOW: int = 60
DNS_THRESHOLD: int = 50
BASELINE_THRESHOLD: int = 3

# pcap config
PCAP_DIR: str = "pcap-dumps"
os.makedirs(PCAP_DIR, exist_ok=True)

# list avail-nets & tables setup
SYN_COUNTER: Dict[str, int] = defaultdict(int)
SYN_TIMESTAMPS: Dict[str, float] = {}
DDoS_COUNTER: Dict[str, Dict[str, int]] = {
    "udp": defaultdict(int),
    "icmp": defaultdict(int),
    "http": defaultdict(int),
}
SCAN_COUNTER: Dict[str, List[Tuple[int, float]]] = defaultdict(list)
DNS_COUNTER: Dict[str, int] = defaultdict(int)
ARP_TABLE: Dict[str, str] = {}
TRAFFIC_PROFILE: Dict[str, List[int]] = defaultdict(list)

print("Available network interfaces:", get_if_list())


# save pcap dump for flagged packets
def save_pcap(packet, tag="suspicious"):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = os.path.join(PCAP_DIR, f"{tag}_{timestamp}.pcap")
    try:
        wrpcap(filename, [packet], append=True)
        print(f"[PCAP] Dumped packet to {filename}")
    except Exception as e:
        print(f"[!] PCAP dump error: {e}")


# dc alerts/log alerts/block_ip if flagged
def send_discord_alert(message: str) -> None:
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": message}, timeout=5)
    except Exception as e:
        print(f"[!] Discord webhook error: {e}")


def log_alert(
    message: str, block_ip_flag: bool = False, ip: Optional[str] = None, packet=None
) -> None:
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
    alert_message = f"{timestamp} ALERT: {message}"
    print(alert_message)

    try:
        with open("ids_alerts.log", "a") as log_file:
            log_file.write(alert_message + "\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

    send_discord_alert(alert_message)

    if packet:
        save_pcap(packet, tag=ip if ip else "alert")

    if block_ip_flag and ip:
        block_ip(ip)


def block_ip(ip: str) -> None:
    try:
        print(f"[ACTION] Blocking {ip} via iptables...")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    except Exception as e:
        print(f"Error blocking IP {ip}: {e}")


# analyzing syn-flood/port-scan/traffic-anomaly/dns-tunneling
def analyze_syn_flood(packet) -> None:
    if packet.haslayer(TCP) and packet[TCP].flags == 2:
        src_ip: str = packet[IP].src
        now: float = time.time()

        if now - SYN_TIMESTAMPS.get(src_ip, 0) > SYN_WINDOW_SIZE:
            SYN_COUNTER[src_ip] = 0
            SYN_TIMESTAMPS[src_ip] = now

        SYN_COUNTER[src_ip] += 1
        if SYN_COUNTER[src_ip] > SYN_THRESHOLD:
            log_alert(
                f"SYN flood from {src_ip} ({SYN_COUNTER[src_ip]} packets).",
                True,
                src_ip,
                packet,
            )


def analyze_ddos(packet) -> None:
    src_ip: str = packet[IP].src

    if packet.haslayer(UDP):
        DDoS_COUNTER["udp"][src_ip] += 1
        if DDoS_COUNTER["udp"][src_ip] > DDoS_THRESHOLD:
            log_alert(f"UDP flood from {src_ip}", True, src_ip, packet)

    elif packet.haslayer(ICMP):
        DDoS_COUNTER["icmp"][src_ip] += 1
        if DDoS_COUNTER["icmp"][src_ip] > DDoS_THRESHOLD:
            log_alert(f"ICMP flood from {src_ip}", True, src_ip, packet)

    elif packet.haslayer(TCP) and packet[TCP].dport == 80:
        DDoS_COUNTER["http"][src_ip] += 1
        if DDoS_COUNTER["http"][src_ip] > DDoS_THRESHOLD:
            log_alert(f"HTTP flood from {src_ip}", True, src_ip, packet)


def analyze_port_scan(packet) -> None:
    if packet.haslayer(TCP) and packet[TCP].flags == 2:
        src_ip: str = packet[IP].src
        dst_port: int = packet[TCP].dport
        now: float = time.time()

        SCAN_COUNTER[src_ip].append((dst_port, now))
        SCAN_COUNTER[src_ip] = [
            (p, t) for p, t in SCAN_COUNTER[src_ip] if now - t < SCAN_WINDOW
        ]

        unique_ports = {p for p, _ in SCAN_COUNTER[src_ip]}
        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            log_alert(
                f"Port scan from {src_ip} ({len(unique_ports)} ports).",
                True,
                src_ip,
                packet,
            )


def analyze_traffic_anomaly(packet) -> None:
    src_ip: str = packet[IP].src
    pkt_size: int = len(packet)
    buf: List[int] = TRAFFIC_PROFILE[src_ip]
    buf.append(pkt_size)

    if len(buf) > 100:
        buf.pop(0)

    if len(buf) > 10:
        mean: float = float(np.mean(buf))
        std: float = float(np.std(buf))
        if std > 0 and pkt_size > mean + BASELINE_THRESHOLD * std:
            log_alert(
                f"Traffic anomaly from {src_ip}: {pkt_size} bytes vs baseline {mean:.1f}±{std:.1f}.",
                False,
                src_ip,
                packet,
            )


def detect_dns_tunneling(packet) -> None:
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        src_ip: str = packet[IP].src
        try:
            domain: str = packet[DNS].qd.qname.decode("utf-8", errors="ignore")
        except Exception:
            domain = str(packet[DNS].qd.qname)

        DNS_COUNTER[src_ip] += 1

        if DNS_COUNTER[src_ip] > DNS_THRESHOLD:
            log_alert(f"DNS tunneling suspected from {src_ip}", True, src_ip, packet)

        if len(domain) > 20 and re.match(r"[a-zA-Z0-9]{10,}\.", domain):
            log_alert(f"Suspicious domain {domain} from {src_ip}", True, src_ip, packet)


def detect_arp_spoof(packet) -> None:
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip: str = packet[ARP].psrc
        mac: str = packet[ARP].hwsrc
        if ip in ARP_TABLE and ARP_TABLE[ip] != mac:
            log_alert(
                f"ARP spoofing: {ip} mapped to {ARP_TABLE[ip]} and {mac}",
                True,
                ip,
                packet,
            )
        ARP_TABLE[ip] = mac


# dispatcher (basically controller)
def analyze_packet(packet) -> None:
    try:
        if packet.haslayer(IP):
            src_ip: str = packet[IP].src
            dst_ip: str = packet[IP].dst

            if src_ip in BLACKLIST_IPS:
                log_alert(
                    f"Blacklisted IP {src_ip} communicating with {dst_ip}",
                    True,
                    src_ip,
                    packet,
                )

            analyze_syn_flood(packet)
            analyze_ddos(packet)
            analyze_port_scan(packet)
            analyze_traffic_anomaly(packet)
            detect_dns_tunneling(packet)

        detect_arp_spoof(packet)
    except Exception as e:
        print(f"[!] Packet analysis error: {e}")


# main loop
def main() -> None:
    try:
        print("[+] IDS running... Press Ctrl+C to stop.")
        sniff(filter="ip or arp", prn=analyze_packet, store=False, iface="wlan0")
    except KeyboardInterrupt:
        print("\n[!] IDS stopped by user.")
    except Exception as e:
        print(f"[!] Main loop error: {e}. Retrying...")
        time.sleep(5)
        main()


if __name__ == "__main__":
    main()
