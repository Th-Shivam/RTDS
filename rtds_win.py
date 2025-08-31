# Enhanced RTDS v2.0 - Windows-ready
# Detects: DDoS (volumetric + SYN flood) & MITM (ARP spoofing)

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
import time, os, argparse
from collections import OrderedDict, defaultdict
import threading

# ----------------- Configuration -----------------
parser = argparse.ArgumentParser(description="Enhanced RTDS - DDoS & MITM Detection")
parser.add_argument("--ddos-threshold", type=int, default=100, help="DDoS packet threshold (pps)")
parser.add_argument("--syn-threshold", type=int, default=50, help="SYN flood threshold (pps)")
parser.add_argument("--log", type=str, default="rtds_alerts.log", help="Log file path")
parser.add_argument("--iface", default="Wi-Fi", help="Network interface (Windows example: Wi-Fi)")
args = parser.parse_args()

DDOS_THRESHOLD = args.ddos_threshold
SYN_THRESHOLD = args.syn_threshold
LOG_FILE = args.log
MAX_ARP_ENTRIES = 1000

# ----------------- State -----------------
ddos_packets = defaultdict(int)
syn_packets = defaultdict(int)
arp_table = OrderedDict()
packet_count = 0
attack_count = 0
start_time = time.time()
last_reset = time.time()

# Local IP of the monitoring machine
LOCAL_IP = get_if_addr(args.iface)

# ----------------- Functions -----------------
def log_alert(message, attack_type="UNKNOWN"):
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding='utf-8') as f:
            f.write(f"[{timestamp}] [{attack_type}] {message}\n")
    except Exception as e:
        print(f"[!] Log error: {e}")

def detect_ddos_attack(packet):
    global packet_count, last_reset, attack_count
    if not packet.haslayer(IP):
        return
    
    src_ip = packet[IP].src
    current_time = time.time()

    # Ignore own machine's packets
    if src_ip == LOCAL_IP:
        return

    # Volumetric DDoS
    ddos_packets[src_ip] += 1
    packet_count += 1

    # Count SYN packets
    if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag
        syn_packets[src_ip] += 1

    # Check every second
    if current_time - last_reset >= 1.0:
        for ip, count in ddos_packets.items():
            if count > DDOS_THRESHOLD:
                attack_count += 1
                alert_msg = f"🚨 DDoS Attack Detected from {ip} - Rate: {count} packets/sec"
                print(f"\033[91m{alert_msg}\033[0m")
                log_alert(alert_msg, "DDOS")
        for ip, count in syn_packets.items():
            if count > SYN_THRESHOLD:
                attack_count += 1
                alert_msg = f"🚨 SYN Flood from {ip} - Rate: {count} SYN packets/sec"
                print(f"\033[91m{alert_msg}\033[0m")
                log_alert(alert_msg, "SYN_FLOOD")
        ddos_packets.clear()
        syn_packets.clear()
        last_reset = current_time

def detect_mitm_attack(packet):
    global attack_count
    if not packet.haslayer(ARP):
        return

    arp_op = packet[ARP].op
    src_ip = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc
    dst_ip = packet[ARP].pdst

    if not src_ip or src_ip == "0.0.0.0" or src_ip.startswith("169.254"):
        return

    # Manage ARP table
    if len(arp_table) >= MAX_ARP_ENTRIES:
        arp_table.popitem(last=False)

    # ARP reply
    if arp_op == 2:
        if src_ip in arp_table:
            if arp_table[src_ip] != src_mac:
                attack_count += 1
                alert_msg = f"⚠ MITM/ARP Spoofing Detected! IP: {src_ip} | Old MAC: {arp_table[src_ip]} → New MAC: {src_mac}"
                print(f"\033[93m{alert_msg}\033[0m")
                log_alert(alert_msg, "MITM")
        else:
            arp_table[src_ip] = src_mac
            print(f"\033[92m✓ New device mapped: {src_ip} → {src_mac}\033[0m")

    # Gratuitous ARP detection
    if arp_op in [1,2] and src_ip in arp_table and arp_table[src_ip] != src_mac:
        alert_msg = f"📡 Suspicious ARP detected: {src_ip} changed MAC {arp_table[src_ip]} → {src_mac}"
        print(f"\033[94m{alert_msg}\033[0m")
        log_alert(alert_msg, "SUSPICIOUS_ARP")

def analyze_packet(packet):
    try:
        detect_ddos_attack(packet)
        detect_mitm_attack(packet)
    except Exception as e:
        print(f"[!] Analysis error: {e}")

def show_statistics():
    uptime = int(time.time() - start_time)
    hours, minutes, seconds = uptime // 3600, (uptime % 3600)//60, uptime %60
    print(f"\033[92m📊 Runtime: {hours:02d}:{minutes:02d}:{seconds:02d} | Packets: {packet_count} | Attacks: {attack_count} | ARP Entries: {len(arp_table)}\033[0m")
    threading.Timer(10.0, show_statistics).start()

# ----------------- Startup -----------------
print("\033[2J\033[H")
print("""
🔐 Enhanced RTDS v2.0 - Windows Ready
🛡 Detection: DDoS (volumetric + SYN) & MITM/ARP Spoofing
--------------------------------------------------
""")
print(f"[*] Interface: {args.iface} | Local IP: {LOCAL_IP}")
print(f"[*] DDoS Threshold: {DDOS_THRESHOLD} pps | SYN Threshold: {SYN_THRESHOLD} pps")
print(f"[*] Log File: {LOG_FILE}\n")
print("[*] Starting monitoring... (Press Ctrl+C to stop)\n")

# Start stats timer
threading.Timer(10.0, show_statistics).start()

# ----------------- Start Sniffing -----------------
try:
    sniff(filter="arp or tcp", prn=analyze_packet, store=0, iface=args.iface)
except PermissionError:
    print("[!] Permission denied! Run as Administrator/Root")
except KeyboardInterrupt:
    print("\n🛑 MONITORING STOPPED")
    uptime = int(time.time() - start_time)
    print(f"📈 Total Runtime: {uptime//3600:02d}:{(uptime%3600)//60:02d}:{uptime%60:02d}")
    print(f"📦 Total Packets Analyzed: {packet_count} | 🚨 Total Attacks Detected: {attack_count}")
    print(f"🗂 ARP Table Entries: {len(arp_table)}")
    print(f"📄 Logs saved in: {LOG_FILE}")