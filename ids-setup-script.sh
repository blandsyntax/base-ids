#!/bin/bash

# IDS Service Setup Script
# This script automatically configures the Python IDS as a Linux systemd service

set -e # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_NAME="IDS Service Setup"
IDS_SCRIPT_NAME="base-ids.py"
SERVICE_NAME="ids.service"
LOG_DIR="/var/log"
SYSTEMD_DIR="/etc/systemd/system"

# Function to print colored output
print_status() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
  echo -e "${BLUE}================================${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}================================${NC}"
}

# Function to check if running as root
check_root() {
  if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    print_status "Usage: sudo ./ids-setup-service.sh"
    exit 1
  fi
}

# Function to detect current user (the one who called sudo)
get_real_user() {
  if [[ -n "$SUDO_USER" ]]; then
    echo "$SUDO_USER"
  else
    echo "$USER"
  fi
}

# Function to get current directory
get_current_dir() {
  pwd
}

# Function to check if IDS script exists
check_ids_script() {
  local current_dir=$(get_current_dir)
  if [[ ! -f "$current_dir/$IDS_SCRIPT_NAME" ]]; then
    print_error "IDS script '$IDS_SCRIPT_NAME' not found in current directory"
    print_status "Please run this script from the directory containing $IDS_SCRIPT_NAME"
    exit 1
  fi
  print_success "Found IDS script: $current_dir/$IDS_SCRIPT_NAME"
}

# Function to install system dependencies
install_dependencies() {
  print_status "Installing system dependencies..."

  # Detect package manager and install dependencies
  if command -v apt-get &>/dev/null; then
    print_status "Detected Debian/Ubuntu system"
    apt-get update
    apt-get install -y python3 python3-pip libpcap-dev tcpdump iptables
  elif command -v yum &>/dev/null; then
    print_status "Detected RHEL/CentOS system"
    yum install -y python3 python3-pip libpcap-devel tcpdump iptables
  elif command -v dnf &>/dev/null; then
    print_status "Detected Fedora system"
    dnf install -y python3 python3-pip libpcap-devel tcpdump iptables
  elif command -v pacman &>/dev/null; then
    print_status "Detected Arch Linux system"
    pacman -S --noconfirm python python-pip libpcap tcpdump iptables
  else
    print_warning "Package manager not detected. Please install manually:"
    print_warning "- python3, python3-pip, libpcap-dev, tcpdump, iptables"
  fi

  print_success "System dependencies installed"
}

# Function to install Python dependencies
install_python_deps() {
  print_status "Installing Python dependencies..."

  # For Arch Linux, try to install system packages first
  if command -v pacman &>/dev/null; then
    print_status "Installing Python packages via pacman..."
    pacman -S --noconfirm python-scapy python-numpy python-requests 2>/dev/null || {
      print_warning "Some packages not available via pacman, falling back to pip"
      # Use --break-system-packages for Arch Linux externally managed environment
      pip3 install --break-system-packages scapy numpy requests
    }
  else
    # For other distributions, use pip as before
    local real_user=$(get_real_user)

    if [[ "$real_user" != "root" ]]; then
      # Try user install first, then system-wide if needed
      sudo -u "$real_user" pip3 install --user scapy numpy requests 2>/dev/null || {
        print_warning "User install failed, trying system-wide install"
        pip3 install scapy numpy requests
      }
    else
      pip3 install scapy numpy requests
    fi
  fi

  print_success "Python dependencies installed"
}

# Function to create systemd service file
create_service_file() {
  local current_dir=$(get_current_dir)
  local real_user=$(get_real_user)

  print_status "Creating systemd service file..."

  cat >"$SYSTEMD_DIR/$SERVICE_NAME" <<EOF
[Unit]
Description=Python Intrusion Detection System
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/bin/python3 $current_dir/$IDS_SCRIPT_NAME
Restart=always
RestartSec=10
User=root
Group=root
WorkingDirectory=$current_dir
StandardOutput=append:$LOG_DIR/ids.log
StandardError=append:$LOG_DIR/ids_error.log
TimeoutStartSec=30
TimeoutStopSec=15

# Environment variables
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

  # Set proper permissions
  chmod 644 "$SYSTEMD_DIR/$SERVICE_NAME"
  print_success "Service file created at $SYSTEMD_DIR/$SERVICE_NAME"
}

# Function to create log files
setup_logging() {
  print_status "Setting up log files..."

  # Create log files
  touch "$LOG_DIR/ids.log" "$LOG_DIR/ids_error.log"
  chmod 644 "$LOG_DIR/ids.log" "$LOG_DIR/ids_error.log"

  # Create local alert log file in script directory
  local current_dir=$(get_current_dir)
  local real_user=$(get_real_user)

  touch "$current_dir/ids_alerts.log"

  if [[ "$real_user" != "root" ]]; then
    chown "$real_user:$real_user" "$current_dir/ids_alerts.log"
  fi

  print_success "Log files configured"
}

# Function to configure systemd service
configure_service() {
  print_status "Configuring systemd service..."

  # Reload systemd daemon
  systemctl daemon-reload

  # Enable service
  systemctl enable "$SERVICE_NAME"

  print_success "Service enabled and configured"
}

# Function to get available network interfaces
show_interfaces() {
  print_status "Available network interfaces:"
  ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  - " $2}' | sed 's/@.*//'
}

# Function to test IDS script
test_ids_script() {
  local current_dir=$(get_current_dir)

  print_status "Testing IDS script syntax..."

  if python3 -m py_compile "$current_dir/$IDS_SCRIPT_NAME"; then
    print_success "IDS script syntax is valid"
  else
    print_error "IDS script has syntax errors"
    return 1
  fi
}

# Function to start service and show status
start_service() {
  print_status "Starting IDS service..."

  if systemctl start "$SERVICE_NAME"; then
    print_success "IDS service started successfully"

    # Show service status
    echo
    print_status "Service Status:"
    systemctl status "$SERVICE_NAME" --no-pager -l

    # Show recent logs
    echo
    print_status "Recent logs (last 10 lines):"
    journalctl -u "$SERVICE_NAME" -n 10 --no-pager

  else
    print_error "Failed to start IDS service"
    print_status "Check logs with: journalctl -u $SERVICE_NAME -f"
    return 1
  fi
}

# Function to show usage instructions
show_usage_instructions() {
  print_header "IDS Service Management Commands"

  echo -e "${GREEN}Service Control:${NC}"
  echo "  sudo systemctl start ids.service     # Start the service"
  echo "  sudo systemctl stop ids.service      # Stop the service"
  echo "  sudo systemctl restart ids.service   # Restart the service"
  echo "  sudo systemctl status ids.service    # Check service status"
  echo
  echo -e "${GREEN}Startup Control:${NC}"
  echo "  sudo systemctl enable ids.service    # Enable on boot (already done)"
  echo "  sudo systemctl disable ids.service   # Disable on boot"
  echo
  echo -e "${GREEN}Log Monitoring:${NC}"
  echo "  journalctl -u ids.service -f         # Follow live service logs"
  echo "  journalctl -u ids.service --since today  # Today's logs"
  echo "  tail -f $(get_current_dir)/ids_alerts.log  # Follow alert logs"
  echo "  tail -f /var/log/ids.log             # Follow output logs"
  echo "  tail -f /var/log/ids_error.log       # Follow error logs"
  echo
  echo -e "${GREEN}Configuration:${NC}"
  echo "  Service file: $SYSTEMD_DIR/$SERVICE_NAME"
  echo "  IDS script: $(get_current_dir)/$IDS_SCRIPT_NAME"
  echo "  Alert logs: $(get_current_dir)/ids_alerts.log"
}

# Function to cleanup on failure
cleanup_on_failure() {
  print_error "Setup failed. Cleaning up..."

  # Stop service if it was started
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true

  # Disable service if it was enabled
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true

  # Remove service file
  rm -f "$SYSTEMD_DIR/$SERVICE_NAME"

  # Reload daemon
  systemctl daemon-reload

  print_status "Cleanup completed"
}

# Main setup function
main() {
  print_header "$SCRIPT_NAME"

  # Trap cleanup on failure
  trap cleanup_on_failure ERR

  # Execute setup steps
  check_root
  check_ids_script
  show_interfaces
  test_ids_script
  install_dependencies
  install_python_deps
  create_service_file
  setup_logging
  configure_service
  start_service

  echo
  print_success "IDS service setup completed successfully!"
  echo
  show_usage_instructions
}

# Call main function with all arguments
main "$@"
