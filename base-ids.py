#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP
import time

# sus IPs if you want to track
BLACKLIST_IPS = ["192.168.1.100", "10.0.0.200"]

#  when ip sends too many syns, so configure it yourself to prevcent attacks
THRESHOLD_SYN_FLOOD = 50
SYN_COUNTER = {}


# logging the ids_alerts
def log_alert(message):
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
    alert_message = f"{timestamp} ALERT: {message}"
    print(alert_message)  # Show alert on screen
    with open("ids_alerts.log", "a") as log_file:
        log_file.write(alert_message + "\n")


# inspect each individual packets
def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src  # inlet
        dst_ip = packet[IP].dst  # outlet

        # blacklisted ip
        if src_ip in BLACKLIST_IPS:
            log_alert(
                f"sus activity detected : Blacklisted IP {src_ip} is talking to {dst_ip}!"
            )

        # detecting  syn flood  (too many connection requests)
        if packet.haslayer(TCP) and packet[TCP].flags == "S":  # syn  packets
            SYN_COUNTER[src_ip] = SYN_COUNTER.get(src_ip, 0) + 1
            if SYN_COUNTER[src_ip] > THRESHOLD_SYN_FLOOD:
                log_alert(
                    f"possible syn flood attack from {src_ip}! more than {THRESHOLD_SYN_FLOOD} syn packets."
                )

        # detect Port Scanning (trying many ports quickly)
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            SYN_COUNTER[(src_ip, dst_port)] = SYN_COUNTER.get((src_ip, dst_port), 0) + 1
            if SYN_COUNTER[(src_ip, dst_port)] > 5:  # Adjust as needed
                log_alert(
                    f"possible port scanning: {src_ip} is trying different ports (latest: {dst_port})."
                )


# starting the sniffing over network traffic
print("IDS is running.")
sniff(filter="ip", prn=analyze_packet, store=False)
