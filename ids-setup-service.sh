#!/bin/bash

# Define the paths
SCRIPT_NAME="base-ids.py"
SERVICE_NAME="ids.service"
SERVICE_PATH="/etc/systemd/system"
SCRIPT_DIR="/usr/local/bin"

# Check if the script and service files exist
if [ ! -f "$SCRIPT_NAME" ]; then
  echo "Error: $SCRIPT_NAME not found!"
  exit 1
fi

if [ ! -f "$SERVICE_NAME" ]; then
  echo "Error: $SERVICE_NAME not found!"
  exit 1
fi

# Copy the script to /usr/local/bin
echo "Copying $SCRIPT_NAME to $SCRIPT_DIR..."
sudo cp "$SCRIPT_NAME" "$SCRIPT_DIR/$SCRIPT_NAME"

# Set the correct permissions for the script
echo "Setting permissions for $SCRIPT_NAME..."
sudo chmod +x "$SCRIPT_DIR/$SCRIPT_NAME"

# Copy the service file to /etc/systemd/system
echo "Copying $SERVICE_NAME to $SERVICE_PATH..."
sudo cp "$SERVICE_NAME" "$SERVICE_PATH/$SERVICE_NAME"

# Reload systemd to recognize the new service
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable the service to start on boot
echo "Enabling $SERVICE_NAME to start on boot..."
sudo systemctl enable "$SERVICE_NAME"

# Start the service
echo "Starting $SERVICE_NAME..."
sudo systemctl start "$SERVICE_NAME"

# Check the status of the service
echo "Checking the status of $SERVICE_NAME..."
sudo systemctl status "$SERVICE_NAME"

echo "Service setup complete!"
