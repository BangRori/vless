#!/bin/bash
set -e

# Install dependencies
echo "Installing dependencies..."
sudo apt update
sudo apt install -y nginx python3 python3-dpkt tcpdump

#telegram
sudo install -m 0600 ./telegram /etc/default/telegram

#keepalive
sudo install -m 0644 ./99-keepalive.conf /etc/sysctl.d/99-keepalive.conf
sudo sysctl -p /etc/sysctl.d/99-keepalive.conf

#nginx-stream
sudo mkdir -p /etc/nginx
sudo install -m 0644 ./nginx-stream.conf /etc/nginx/nginx.conf
sudo touch /etc/nginx/graylist.conf

#dpi-alert
#sudo apt install python3-dpkt
sudo mkdir -p /var/log/dpi-alert
sudo mkdir -p /var/log/tcpdump
sudo mkdir -p /etc/dpi-alert
sudo install -m 0644 ./dpi-alert/dpi_detector.yml /etc/dpi-alert/dpi_detector.yml
sudo install -m 0644 ./dpi-alert/dpi_detector.py  /usr/local/sbin/dpi_detector.py
sudo install -m 0644 ./dpi-alert/dpi-detector.service /etc/systemd/system/dpi-detector.service
sudo install -m 0644 ./dpi-alert/dpi-detector.timer /etc/systemd/system/dpi-detector.timer
sudo install -m 0700 ./dpi-alert/tcpdump-tls.sh /usr/local/sbin/tcpdump-tls.sh
sudo install -m 0644 ./dpi-alert/tcpdump-tls.service /etc/systemd/system/tcpdump-tls.service
sudo systemctl daemon-reload
sudo systemctl enable --now dpi-detector.timer
sudo systemctl enable --now tcpdump-tls.service