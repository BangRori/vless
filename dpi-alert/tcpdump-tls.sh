#!/bin/bash

PCAP_DIR="/var/log/tcpdump"
MAX_AGE_MIN=30  # удалять файлы старше 30 минут

# Чистим старые файлы перед запуском
find "$PCAP_DIR" -name "tls-*.pcap" -mmin +$MAX_AGE_MIN -delete

exec /usr/sbin/tcpdump \
    -i eth0 \
    -Z root \
    -w "$PCAP_DIR/tls-%s.pcap" \
    -G 300 \
    -n \
    'tcp port 443 and tcp[tcpflags] & tcp-syn != 0'
