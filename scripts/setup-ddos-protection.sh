#!/bin/bash

# @note OS-level DDoS protection setup script for Linux
# This script configures kernel parameters and iptables rules to protect against network-layer attacks

echo "=================================="
echo "OS-Level DDoS Protection Setup"
echo "=================================="
echo ""
echo "This script will configure:"
echo "- TCP SYN flood protection"
echo "- Connection rate limiting"
echo "- ICMP flood protection"
echo ""
echo "NOTE: Requires root privileges"
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo ./setup-ddos-protection.sh)"
    exit 1
fi

echo "[1/4] Configuring kernel parameters for SYN flood protection..."

sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.tcp_syn_retries=2

echo "[2/4] Configuring connection limits..."

sysctl -w net.core.somaxconn=1024
sysctl -w net.ipv4.tcp_max_tw_buckets=1440000
sysctl -w net.ipv4.tcp_fin_timeout=15

echo "[3/4] Configuring ICMP flood protection..."

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.icmp_ratelimit=100

echo "[4/4] Setting up iptables rules..."

iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A INPUT -f -j DROP

iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

echo ""
echo "✓ DDoS protection configured successfully!"
echo ""
echo "To make these settings persistent across reboots:"
echo "1. Add sysctl settings to /etc/sysctl.conf"
echo "2. Save iptables rules: iptables-save > /etc/iptables/rules.v4"
echo ""
echo "Current protection settings:"
echo "- SYN cookies: enabled"
echo "- Max SYN backlog: 2048"
echo "- Connection rate limit: 10 connections per 60 seconds per IP"
echo "- ICMP rate limit: 100 packets/sec"
echo ""
