#!/usr/bin/env python3
import time
from collections import defaultdict
from scapy.all import ARP, get_if_addr
import ipaddress

class EnhancedARPDetector:
    def __init__(self, interface):
        self.arp_table = {}
        self.mac_vendors = {}
        self.network_topology = defaultdict(set)
        self.arp_request_counts = defaultdict(int)
        self.gratuitous_arp_count = defaultdict(int)
        self.mac_change_history = defaultdict(list)
        self.trusted_devices = set()
        
        try:
            self.local_ip = get_if_addr(interface)
            self.network = ipaddress.IPv4Network(f"{self.local_ip}/24", strict=False)
        except:
            self.local_ip = None
            self.network = None
    
    def analyze_arp_packet(self, packet):
        if not packet.haslayer(ARP):
            return None
            
        arp = packet[ARP]
        src_ip, src_mac = arp.psrc, arp.hwsrc
        dst_ip, dst_mac = arp.pdst, arp.hwdst
        op = arp.op
        current_time = time.time()
        
        alerts = []
        
        # Skip invalid entries
        if not src_ip or src_ip == "0.0.0.0":
            return None
            
        # Detect gratuitous ARP
        if op == 2 and src_ip == dst_ip:  # ARP reply to self
            self.gratuitous_arp_count[src_ip] += 1
            if self.gratuitous_arp_count[src_ip] > 3:
                alerts.append(f"Excessive gratuitous ARP from {src_ip}")
        
        # Track ARP request flooding
        if op == 1:  # ARP request
            self.arp_request_counts[src_ip] += 1
            if self.arp_request_counts[src_ip] > 50:
                alerts.append(f"ARP request flooding from {src_ip}")
        
        # MAC address conflict detection
        if src_ip in self.arp_table:
            old_mac = self.arp_table[src_ip]
            if old_mac != src_mac:
                # Record MAC change
                self.mac_change_history[src_ip].append({
                    'old_mac': old_mac,
                    'new_mac': src_mac,
                    'timestamp': current_time
                })
                
                # Check for rapid MAC changes (strong spoofing indicator)
                recent_changes = [
                    change for change in self.mac_change_history[src_ip]
                    if current_time - change['timestamp'] < 300  # 5 minutes
                ]
                
                if len(recent_changes) > 2:
                    alerts.append(f"🚨 CRITICAL: Rapid MAC changes for {src_ip}")
                elif self._is_likely_spoofing(src_ip, old_mac, src_mac):
                    alerts.append(f"⚠️ MITM: MAC conflict {src_ip}: {old_mac} → {src_mac}")
        
        # Update ARP table
        self.arp_table[src_ip] = src_mac
        
        # Network topology learning
        if self.network and ipaddress.IPv4Address(src_ip) in self.network:
            self.network_topology[src_mac].add(src_ip)
            
            # Detect MAC address reuse across IPs
            if len(self.network_topology[src_mac]) > 1:
                ips = list(self.network_topology[src_mac])
                alerts.append(f"🔍 MAC reuse: {src_mac} used by {ips}")
        
        return alerts[0] if alerts else None
    
    def _is_likely_spoofing(self, ip, old_mac, new_mac):
        # Check if this is a known trusted device
        if ip in self.trusted_devices:
            return False
            
        # Check vendor consistency
        old_vendor = self._get_mac_vendor(old_mac)
        new_vendor = self._get_mac_vendor(new_mac)
        
        if old_vendor and new_vendor and old_vendor != new_vendor:
            return True  # Different vendors = likely spoofing
            
        # Check for common spoofing patterns
        if new_mac.startswith('00:00:00') or new_mac == 'ff:ff:ff:ff:ff:ff':
            return True
            
        return False
    
    def _get_mac_vendor(self, mac):
        oui = mac[:8].upper()
        # Simplified vendor detection (in real implementation, use OUI database)
        vendors = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU',
            '00:0C:29': 'VMware'
        }
        return vendors.get(oui, 'Unknown')
