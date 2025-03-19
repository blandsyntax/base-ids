#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, ARP
import time
import os

# sus IPs if you want to track
BLACKLIST_IPS = ["192.168.1.100", "10.0.0.200"]

#  when ip sends too many syns, so configure it yourself to prevent attacks
THRESHOLD_SYN_FLOOD = 50
SYN_COUNTER = {}

# keep track of IP -> MAC mapping to detect ARP spoofing
ARP_TABLE = {}


# logging the ids_alerts
def log_alert(message, block_ip_flag=False, ip=None):
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
    alert_message = f"{timestamp} ALERT: {message}"
    print(alert_message)  # Show alert on screen
    with open("ids_alerts.log", "a") as log_file:
        log_file.write(alert_message + "\n")

    # if blocking is enabled, block the attacker IP
    if block_ip_flag and ip:
        block_ip(ip)


# firewall auto-blocking for threats
def block_ip(ip):
    print(f"[ACTION] Blocking {ip} using iptables")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")


# inspect each individual packet
def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src  # inlet
        dst_ip = packet[IP].dst  # outlet

        # blacklisted ip detection
        if src_ip in BLACKLIST_IPS:
            log_alert(
                f"sus activity detected : Blacklisted IP {src_ip} is talking to {dst_ip}!",
                True,
                src_ip,
            )

        # detecting syn flood  (too many connection requests)
        if packet.haslayer(TCP) and packet[TCP].flags == "S":  # syn  packets
            SYN_COUNTER[src_ip] = SYN_COUNTER.get(src_ip, 0) + 1
            if SYN_COUNTER[src_ip] > THRESHOLD_SYN_FLOOD:
                log_alert(
                    f"possible syn flood attack from {src_ip}! more than {THRESHOLD_SYN_FLOOD} syn packets.",
                    True,
                    src_ip,
                )

        # detect Port Scanning (trying many ports quickly)
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            SYN_COUNTER[(src_ip, dst_port)] = SYN_COUNTER.get((src_ip, dst_port), 0) + 1
            if SYN_COUNTER[(src_ip, dst_port)] > 5:  # Adjust as needed
                log_alert(
                    f"possible port scanning: {src_ip} is trying different ports (latest: {dst_port})."
                )


# detecting arp spoofing attempts
def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply packet
        sender_ip = packet[ARP].psrc  # the ip being claimed (i hope this works pls)
        sender_mac = packet[ARP].hwsrc  # the mac address claiming it

        # if an IP is using multiple MACs, it might be an attack
        if sender_ip in ARP_TABLE and ARP_TABLE[sender_ip] != sender_mac:
            log_alert(
                f"possible ARP spoofing detected! {sender_ip} is using multiple MAC addresses!",
                True,
                sender_ip,
            )

        # update ARP table
        ARP_TABLE[sender_ip] = sender_mac


# start sniffing network packets for threats
print("ids is indeed running. monitoring for threats...")

# sniff for IP/TCP attacks
sniff(filter="ip", prn=analyze_packet, store=False)

# sniff for ARP spoofing attempts
sniff(filter="arp", prn=detect_arp_spoof, store=False)
