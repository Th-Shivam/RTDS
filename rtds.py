#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
import time

# Clear screen and show banner
print("\033[2J\033[H")
print("""
🔐 RTDS v1.0 - Real-Time Threat Detection System
🛡️  Monitoring: DDoS & MITM Attacks
🕒 Starting network monitoring...
--------------------------------------------------
""")

# Configuration
DDOS_THRESHOLD = 100  # packets per second
ddos_counter = 0
start_time = time.time()

arp_table = {}  # To store IP -> MAC mapping
LOG_FILE = "alerts.log"

def detect_attacks(packet):
    global ddos_counter, start_time

    current_time = time.time()

    # --- DDoS Detection (High packet rate from multiple IPs) ---
    if packet.haslayer(IP):
        ddos_counter += 1

        # Check every 1 second
        if current_time - start_time >= 1:
            if ddos_counter > DDOS_THRESHOLD:
                print(f"\033[91m🚨 ALERT: DDoS Attack Detected! Rate: {ddos_counter} pps\033[0m")
                with open(LOG_FILE, "a") as f:
                    f.write(f"{time.ctime()} - DDoS: {ddos_counter} pps (Possible SYN Flood)\n")
            ddos_counter = 0
            start_time = current_time

    # --- MITM Detection (ARP Spoofing) ---
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        # Skip invalid IPs (DHCP, APIPA)
        if ip == "0.0.0.0" or ip.startswith("169.254"):
            return

        if ip in arp_table:
            if arp_table[ip] != mac:
                print(f"\033[93m⚠️  ALERT: MITM (ARP Spoofing) Detected!\033[0m IP: {ip} | Old MAC: {arp_table[ip]} → New MAC: {mac}")
                with open(LOG_FILE, "a") as f:
                    f.write(f"{time.ctime()} - MITM: IP {ip} changed MAC from {arp_table[ip]} to {mac}\n")
        else:
            arp_table[ip] = mac

# Start monitoring
print("[*] Monitoring live traffic... (Press Ctrl+C to stop)")
try:
    sniff(prn=detect_attacks, store=0)
except KeyboardInterrupt:
    print("\n[*] Stopping monitor...")

print("\n[*] RTDS Scan Complete.")
print(f"📄 Logs saved in: {LOG_FILE}")