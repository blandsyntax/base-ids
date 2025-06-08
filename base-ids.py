#!/usr/bin/env python3
from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, ARP, DNS
import time
import os
import requests
import re
import numpy as np
from collections import defaultdict

# List available network interfaces
print("Available network interfaces:", get_if_list())

# Suspect IPs to monitor
BLACKLIST_IPS = ["192.168.1.100", "10.0.0.200"]

# Detection thresholds and counters
SYN_THRESHOLD = 50  # SYN flood threshold (packets per time window)
SYN_WINDOW_SIZE = 60  # Time window in seconds for SYN flood
SYN_COUNTER = defaultdict(int)
SYN_TIMESTAMPS = {}

DDoS_THRESHOLD = 100  # DDoS threshold (packets per time window)
DDoS_COUNTER = {'udp': defaultdict(int), 'icmp': defaultdict(int), 'http': defaultdict(int)}

PORT_SCAN_THRESHOLD = 5  # Port scan detection threshold
SCAN_WINDOW = 60  # Time window for port scan detection
SCAN_COUNTER = {}

DNS_THRESHOLD = 50  # DNS tunneling threshold (queries per time window)
DNS_COUNTER = defaultdict(int)

ARP_TABLE = {}  # ARP spoofing detection table

# Store packet sizes for anomaly detection
TRAFFIC_PROFILE = defaultdict(list)  # Store actual packet sizes for std dev calculation
BASELINE_THRESHOLD = 3  # Anomaly threshold based on std deviation

# Logging function to log alerts
def log_alert(message, block_ip_flag=False, ip=None):
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
    alert_message = f"{timestamp} ALERT: {message}"
    print(alert_message)  # Print alert to the console
    try:
        with open("ids_alerts.log", "a") as log_file:
            log_file.write(alert_message + "\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

    # Optionally block the IP address
    if block_ip_flag and ip:
        block_ip(ip)

# Firewall auto-blocking function
def block_ip(ip):
    try:
        print(f"[ACTION] Blocking {ip} using iptables")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    except Exception as e:
        print(f"Error blocking IP {ip}: {e}")

# SYN flood detection function
def analyze_syn_flood(packet):
    try:
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag (use numeric value)
            src_ip = packet[IP].src
            current_time = time.time()

            # Initialize timestamp if not seen before
            if src_ip not in SYN_TIMESTAMPS:
                SYN_TIMESTAMPS[src_ip] = current_time
                SYN_COUNTER[src_ip] = 0

            time_elapsed = current_time - SYN_TIMESTAMPS[src_ip]
            if time_elapsed > SYN_WINDOW_SIZE:
                # Reset counter after the time window expires
                SYN_COUNTER[src_ip] = 0
                SYN_TIMESTAMPS[src_ip] = current_time

            SYN_COUNTER[src_ip] += 1
            if SYN_COUNTER[src_ip] > SYN_THRESHOLD:
                log_alert(f"Possible SYN flood attack from {src_ip}. {SYN_COUNTER[src_ip]} SYN packets detected in {SYN_WINDOW_SIZE} seconds.", True, src_ip)
    except Exception as e:
        print(f"Error in SYN flood analysis: {e}")

# DDoS detection function for UDP, ICMP, and HTTP floods
def analyze_ddos(packet):
    try:
        src_ip = packet[IP].src

        if packet.haslayer(UDP):
            DDoS_COUNTER['udp'][src_ip] += 1
            if DDoS_COUNTER['udp'][src_ip] > DDoS_THRESHOLD:
                log_alert(f"Possible UDP flood from {src_ip}. {DDoS_COUNTER['udp'][src_ip]} UDP packets detected.", True, src_ip)

        elif packet.haslayer(ICMP):
            DDoS_COUNTER['icmp'][src_ip] += 1
            if DDoS_COUNTER['icmp'][src_ip] > DDoS_THRESHOLD:
                log_alert(f"Possible ICMP flood from {src_ip}. {DDoS_COUNTER['icmp'][src_ip]} ICMP packets detected.", True, src_ip)

        elif packet.haslayer(TCP) and packet[TCP].dport == 80:  # HTTP traffic
            DDoS_COUNTER['http'][src_ip] += 1
            if DDoS_COUNTER['http'][src_ip] > DDoS_THRESHOLD:
                log_alert(f"Possible HTTP flood from {src_ip}. {DDoS_COUNTER['http'][src_ip]} HTTP requests detected.", True, src_ip)
    except Exception as e:
        print(f"Error in DDoS analysis: {e}")

# Port scanning detection function - FIXED
def analyze_port_scan(packet):
    try:
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN packets
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            current_time = time.time()

            # Create a unique key for this IP-port combination
            scan_key = (src_ip, dst_port)
            
            if scan_key not in SCAN_COUNTER:
                SCAN_COUNTER[scan_key] = current_time

            # Clean up old entries - create new dict to avoid modification during iteration
            current_entries = {}
            for key, timestamp in SCAN_COUNTER.items():
                if current_time - timestamp < SCAN_WINDOW:
                    current_entries[key] = timestamp
            
            SCAN_COUNTER.clear()
            SCAN_COUNTER.update(current_entries)

            # Count unique ports scanned by this IP
            ports_scanned = len([key for key in SCAN_COUNTER.keys() if key[0] == src_ip])
            
            if ports_scanned > PORT_SCAN_THRESHOLD:
                log_alert(f"Possible port scan detected from {src_ip}. Scanning {ports_scanned} ports.", True, src_ip)
    except Exception as e:
        print(f"Error in port scan analysis: {e}")

# Traffic anomaly detection using behavior analysis - FIXED
def analyze_traffic_anomaly(packet):
    try:
        src_ip = packet[IP].src
        packet_size = len(packet)

        # Store packet sizes for this IP
        TRAFFIC_PROFILE[src_ip].append(packet_size)
        
        # Only analyze if we have enough samples
        if len(TRAFFIC_PROFILE[src_ip]) > 10:
            # Keep only recent packet sizes (last 100 packets per IP)
            if len(TRAFFIC_PROFILE[src_ip]) > 100:
                TRAFFIC_PROFILE[src_ip] = TRAFFIC_PROFILE[src_ip][-100:]
            
            # Calculate statistics
            packet_sizes = TRAFFIC_PROFILE[src_ip]
            mean_size = np.mean(packet_sizes)
            stddev_size = np.std(packet_sizes)
            
            # Check for anomaly (avoid division by zero)
            if stddev_size > 0 and packet_size > mean_size + BASELINE_THRESHOLD * stddev_size:
                log_alert(f"Traffic anomaly detected from {src_ip}. Packet size {packet_size} deviates from baseline (mean: {mean_size:.2f}, std: {stddev_size:.2f}).")
    except Exception as e:
        print(f"Error in traffic anomaly analysis: {e}")

# DNS tunneling detection function
def detect_dns_tunneling(packet):
    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS Query
            src_ip = packet[IP].src
            
            # Safely decode domain name
            try:
                domain = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
            except:
                domain = str(packet[DNS].qd.qname)

            DNS_COUNTER[src_ip] += 1

            if DNS_COUNTER[src_ip] > DNS_THRESHOLD:
                log_alert(f"Possible DNS tunneling from {src_ip}. {DNS_COUNTER[src_ip]} DNS queries detected.", True, src_ip)

            # Check for suspicious domains (long random strings)
            if len(domain) > 20 and re.match(r'[a-zA-Z0-9]{10,}\.', domain):
                log_alert(f"Suspicious domain {domain} detected from {src_ip}. Possible DNS tunneling.", True, src_ip)
    except Exception as e:
        print(f"Error in DNS tunneling detection: {e}")

# ARP spoofing detection function
def detect_arp_spoof(packet):
    try:
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply packet
            sender_ip = packet[ARP].psrc  # IP being claimed
            sender_mac = packet[ARP].hwsrc  # MAC address claiming it

            if sender_ip in ARP_TABLE and ARP_TABLE[sender_ip] != sender_mac:
                log_alert(f"Possible ARP spoofing detected! {sender_ip} is using multiple MAC addresses (Old: {ARP_TABLE[sender_ip]}, New: {sender_mac}).", True, sender_ip)

            ARP_TABLE[sender_ip] = sender_mac
    except Exception as e:
        print(f"Error in ARP spoofing detection: {e}")

# Main packet analysis function
def analyze_packet(packet):
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Blacklist detection
            if src_ip in BLACKLIST_IPS:
                log_alert(f"Suspicious activity detected: Blacklisted IP {src_ip} is talking to {dst_ip}!", True, src_ip)

            # Run analysis functions
            analyze_syn_flood(packet)
            analyze_ddos(packet)
            analyze_port_scan(packet)
            analyze_traffic_anomaly(packet)
            detect_dns_tunneling(packet)
        
        # ARP spoofing detection runs on all packets
        detect_arp_spoof(packet)
            
    except Exception as e:
        print(f"Error analyzing packet: {e}")

# Main function with error handling
def main():
    try:
        print("IDS is running. Monitoring for threats...")
        print("Press Ctrl+C to stop")
        
        # Start sniffing network packets with error handling
        sniff(filter="ip or arp", prn=analyze_packet, store=False, iface="wlan0")
        
    except KeyboardInterrupt:
        print("\nIDS stopped by user")
    except Exception as e:
        print(f"Error in main sniffing loop: {e}")
        print("Retrying in 5 seconds...")
        time.sleep(5)
        main()  # Restart

if __name__ == "__main__":
    main()
