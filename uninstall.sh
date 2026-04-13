#!/bin/bash

# Uninstall script for VLESS services and configurations

# Stop all VLESS services
systemctl stop vless

# Disable VLESS services
systemctl disable vless

# Remove VLESS service file
rm -f /etc/systemd/system/vless.service

# Remove VLESS configuration files
rm -rf /etc/vless/

# Remove VLESS binaries (if any)
rm -f /usr/local/bin/vless

# Display status message
echo 'VLESS has been uninstalled successfully.'

# Optionally, you can remove any other related files or directories
# rm -rf /path/to/other/vless/files
