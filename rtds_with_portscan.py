#!/usr/bin/env python3
"""
RTDS with Enhanced Port Scan Detection
Integrated threat detection system
"""

from scapy.all import *
from collections import defaultdict
import time
import threading
import json
from port_scan_detector import EnhancedPortScanDetector

class IntegratedRTDS:
    def __init__(self):
        self.port_detector = EnhancedPortScanDetector()
        self.ddos_threshold = 100
        self.packet_counts = defaultdict(list)
        self.arp_table = {}
        
    def analyze_packet(self, packet):
        """Unified packet analysis for all threats"""
        current_time = time.time()
        alerts = []
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            
            # DDoS Detection
            self.packet_counts[src_ip].append(current_time)
            self.packet_counts[src_ip] = [
                t for t in self.packet_counts[src_ip] 
                if current_time - t <= 60
            ]
            
            if len(self.packet_counts[src_ip]) > self.ddos_threshold:
                alerts.append(f"💥 DDoS Attack: {src_ip} - {len(self.packet_counts[src_ip])} pps")
        
        # Port Scan Detection
        if packet.haslayer(TCP):
            port_alerts = self.port_detector.detect_scan_type(packet)
            if port_alerts:
                alerts.extend(port_alerts)
        
        # ARP Spoofing Detection
        if packet.haslayer(ARP):
            arp_alerts = self._check_arp_spoofing(packet)
            if arp_alerts:
                alerts.append(arp_alerts)
        
        return alerts
    
    def _check_arp_spoofing(self, packet):
        """Check for ARP spoofing attacks"""
        if packet[ARP].op == 2:  # ARP reply
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            
            if ip in self.arp_table and self.arp_table[ip] != mac:
                return f"⚠️ ARP Spoofing: {ip} MAC changed {self.arp_table[ip]} → {mac}"
            
            self.arp_table[ip] = mac
        return None
    
    def start_monitoring(self, interface=None):
        """Start integrated threat monitoring"""
        print("🛡️ RTDS Enhanced - Multi-Threat Detection")
        print("🔍 Monitoring: DDoS | Port Scans | ARP Spoofing")
        print("=" * 50)
        
        def packet_handler(packet):
            alerts = self.analyze_packet(packet)
            for alert in alerts:
                timestamp = time.strftime('%H:%M:%S')
                print(f"[{timestamp}] {alert}")
        
        try:
            sniff(iface=interface, prn=packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n🛑 RTDS monitoring stopped")

if __name__ == "__main__":
    rtds = IntegratedRTDS()
    rtds.start_monitoring()
