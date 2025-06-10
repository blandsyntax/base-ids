# Base IDS - Python Intrusion Detection System

A lightweight, real-time Intrusion Detection System (IDS) written in Python that monitors network traffic and alerts on suspicious activities including blacklisted IPs, potential SYN flood attacks, and port scanning attempts.

## Features

- **Real-time Network Monitoring**: Captures and analyzes network packets in real-time
- **Threat Detection**: Identifies suspicious activities including:
  - Blacklisted IP connections
  - Potential SYN flood attacks
  - Port scanning attempts
- **Automated Service Setup**: One-command installation and service configuration
- **Comprehensive Logging**: Multiple log levels with rotation and management
- **Cross-platform Support**: Works on major Linux distributions (Ubuntu/Debian, RHEL/CentOS, Fedora, Arch Linux)

## System Requirements

### Dependencies
- **Python**: Version 3.6 or higher
- **System packages**: `libpcap-dev`, `tcpdump`, `iptables`
- **Python packages**: `scapy`, `numpy`, `requests`

### Supported Operating Systems
- Ubuntu/Debian (apt-get)
- RHEL/CentOS (yum)
- Fedora (dnf)
- Arch Linux (pacman)

## Quick Installation

### Quick thing to change, go to the base-ids folder and edit the ids.service, replace syn with your username wherever it is mentioned.(important )


### Automated Setup (Recommended)
```bash
git clone <repository-url>
cd base-ids
chmod +x ids-setup-service.sh
sudo ./ids-setup-service.sh
```

The setup script automatically:
- Installs all system and Python dependencies
- Creates and configures the systemd service
- Sets up logging infrastructure
- Starts the IDS service
- Enables automatic startup on boot

### Manual Installation
If you prefer to install dependencies manually:

**For Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip libpcap-dev tcpdump iptables
pip3 install --user scapy numpy requests
```

**For Arch Linux:**
```bash
sudo pacman -S python python-pip libpcap tcpdump iptables
sudo pacman -S python-scapy python-numpy python-requests
# Or if packages unavailable: pip3 install --break-system-packages scapy numpy requests
```

## Usage

### Running as a Service (Recommended)

**Start the service:**
```bash
sudo systemctl start ids.service
```

**Stop the service:**
```bash
sudo systemctl stop ids.service
```

**Check service status:**
```bash
sudo systemctl status ids.service
```

**Enable/disable automatic startup:**
```bash
sudo systemctl enable ids.service   # Enable on boot
sudo systemctl disable ids.service  # Disable on boot
```

### Running as a Standalone Process

For testing or temporary monitoring:
```bash
sudo python3 base-ids.py
```

**Note**: Root privileges are required for network packet capture.

## Log Monitoring

### Service Logs
```bash
# Follow live service logs
journalctl -u ids.service -f

# View recent logs
journalctl -u ids.service -n 50

# View logs from today
journalctl -u ids.service --since today
```

### Alert Logs
```bash
# Follow live alerts
tail -f ids_alerts.log

# View system logs
tail -f /var/log/ids.log
tail -f /var/log/ids_error.log
```

## Service Management

### Complete Service Removal
```bash
sudo systemctl stop ids.service
sudo systemctl disable ids.service
sudo rm /etc/systemd/system/ids.service
sudo systemctl daemon-reload
```

### Service Configuration
The service file is located at `/etc/systemd/system/ids.service` and can be modified if needed:
- **Working Directory**: Automatically set to script location
- **User/Group**: Runs as root (required for packet capture)
- **Restart Policy**: Automatic restart on failure
- **Logging**: Configured with proper log rotation

## Network Interface Selection

The setup script automatically detects available network interfaces. You can view them with:
```bash
ip link show
```

To modify which interface the IDS monitors, edit the `base-ids.py` script and update the interface parameter.

## Use Cases

### Home Network Security
- Deploy on your home router or gateway
- Monitor incoming/outgoing traffic for threats
- Detect unauthorized access attempts

### Personal Server Protection  
- Install on personal servers (web, mail, etc.)
- Monitor for brute force attacks
- Detect port scanning activities

### Educational/Testing Environment
- Practice penetration testing techniques
- Learn about network security monitoring
- Test SYN flood protection mechanisms

### Small Business Networks
- Cost-effective network monitoring solution
- Basic intrusion detection capabilities
- Complement existing security infrastructure

## Troubleshooting

### Common Issues

**Permission Denied:**
- Ensure script is run with sudo privileges
- Verify user has access to network interfaces

**Python Package Installation Errors:**
- On Arch Linux, the script handles externally-managed environments automatically
- For other systems, try: `pip3 install --user <package_name>`

**Service Won't Start:**
- Check syntax: `python3 -m py_compile base-ids.py`
- Verify dependencies: `python3 -c "import scapy, numpy, requests"`
- Check logs: `journalctl -u ids.service -n 20`

**No Network Traffic Detected:**
- Verify correct network interface is selected
- Check interface is up: `ip link show`
- Ensure sufficient privileges for packet capture

### Getting Help

1. **Check service status**: `sudo systemctl status ids.service`
2. **Review logs**: `journalctl -u ids.service -f`
3. **Test script syntax**: `python3 -m py_compile base-ids.py`
4. **Verify dependencies**: Check all required packages are installed

## Security Considerations

- **Root Privileges**: Required for packet capture - ensure system is properly secured
- **Log Management**: Monitor log file sizes and implement rotation if needed
- **Network Impact**: Minimal performance impact on most systems
- **False Positives**: Review alerts regularly and tune detection rules as needed

## Future Enhancements
- Email/SMS alert notifications
