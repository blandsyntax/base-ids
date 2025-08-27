# Abyss IDS

A lightweight, real-time Intrusion Detection System (IDS) written in
Python.\
Monitors network traffic and alerts on:\
- Blacklisted IP connections\
- SYN flood attempts\
- Port scans

------------------------------------------------------------------------

## Requirements

-   **Python** ≥ 3.10\
-   System: `libpcap-dev`, `tcpdump`, `iptables`\
-   Python: `scapy`, `numpy`, `requests`

Supported distros: Ubuntu/Debian, RHEL/CentOS, Fedora, Arch Linux.

------------------------------------------------------------------------

## Quick Install

``` bash
git clone <repo-url>
cd abyss-ids
chmod +x setup.sh
sudo ./setup.sh
```

The script will install dependencies, configure logs, and set up a
systemd service.

------------------------------------------------------------------------

## Usage

### Service

``` bash
sudo systemctl start abyssids.service
sudo systemctl stop abyssids.service
sudo systemctl status abyssids.service
sudo systemctl enable abyssids.service
```

### Standalone

``` bash
sudo python3 abyss-ids.py
```

------------------------------------------------------------------------

## Logs

``` bash
journalctl -u abyssids.service -f      # Service logs
tail -f abyss_alerts.log               # Alerts
tail -f /var/log/ids.log               # Output
tail -f /var/log/ids_error.log         # Errors
```

------------------------------------------------------------------------

## Manage / Remove

``` bash
sudo systemctl stop abyssids.service
sudo systemctl disable abyssids.service
sudo rm /etc/systemd/system/abyssids.service
sudo systemctl daemon-reload
```

------------------------------------------------------------------------

## Notes

-   Must run as **root** for packet capture.\
-   Default interface can be changed inside `abyss-ids.py`.\
-   Lightweight enough for home labs, servers, or small networks.
