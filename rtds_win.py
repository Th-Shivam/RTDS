# Windows-compatible version (shebang removed)
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
import time
import os
import argparse
from collections import OrderedDict

# Configuration
parser = argparse.ArgumentParser(description="RTDS - Real-Time Threat Detection System")
parser.add_argument("--threshold", type=int, default=100, help="DDoS packet threshold (pps)")
parser.add_argument("--log", type=str, default="alerts.log", help="Log file path")
parser.add_argument("--iface", default=None, help="Network interface to use (e.g., Wi-Fi)")
args = parser.parse_args()

DDOS_THRESHOLD = args.threshold
LOG_FILE = args.log
MAX_ARP_ENTRIES = 1000
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB

# State
ddos_counter = 0
start_time = time.time()
arp_table = OrderedDict()

# Clear screen and show banner
print("\033[2J\033[H")
print("""
🔐 RTDS v1.0 - Real-Time Threat Detection System
🛡️  Monitoring: DDoS & MITM Attacks
🕒 Starting network monitoring...
--------------------------------------------------
""")

def log_alert(message):
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
            os.rename(LOG_FILE, f"{LOG_FILE}.{time.ctime().replace(' ', '_')}")
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.ctime()} - {message}\n")
    except IOError as e:
        print(f"\033[91m[!] Error writing to log file: {e}\033[0m")

def detect_attacks(packet):
    global ddos_counter, start_time

    current_time = time.time()

    # --- DDoS Detection (SYN Flood) ---
    if packet.haslayer(TCP) and packet[TCP].flags == "S":  # Check for SYN packets
        ddos_counter += 1
        if current_time - start_time >= 1:
            if ddos_counter > DDOS_THRESHOLD:
                print(f"\033[91m🚨 ALERT: DDoS Attack Detected! Rate: {ddos_counter} pps\033[0m")
                log_alert(f"DDoS: {ddos_counter} pps (Possible SYN Flood)")
            ddos_counter = 0
            start_time = current_time

    # --- MITM Detection (ARP Spoofing) ---
    if packet.haslayer(ARP) and (packet[ARP].op == 2 or packet[ARP].psrc == packet[ARP].pdst):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip == "0.0.0.0" or ip.startswith("169.254"):
            return

        if len(arp_table) >= MAX_ARP_ENTRIES:
            arp_table.popitem(last=False)

        if ip in arp_table:
            if arp_table[ip] != mac:
                print(f"\033[93m⚠️  ALERT: MITM (ARP Spoofing) Detected!\033[0m IP: {ip} | Old MAC: {arp_table[ip]} → New MAC: {mac}")
                log_alert(f"MITM: IP {ip} changed MAC from {arp_table[ip]} to {mac}")
        else:
            arp_table[ip] = mac

# Start monitoring
print("[*] Monitoring live traffic... (Press Ctrl+C to stop)")
try:
    sniff(filter="arp or tcp", prn=detect_attacks, store=0, iface=args.iface, promisc=True)
except Exception as e:
    print(f"\033[91m[!] Error in sniffing: {e}\033[0m")
except KeyboardInterrupt:
    print("\n[*] Stopping monitor...")

print("\n[*] RTDS Scan Complete.")
print(f"📄 Logs saved in: {LOG_FILE}")