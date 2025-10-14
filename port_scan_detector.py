#!/usr/bin/env python3
from scapy.all import *
from collections import defaultdict
import time

class PortScanDetector:
    def __init__(self, threshold=20, time_window=60):
        self.threshold = threshold
        self.time_window = time_window
        self.connections = defaultdict(lambda: defaultdict(list))
    
    def detect_scan(self, packet):
        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            current_time = time.time()
            
            # Track connections per IP
            self.connections[src_ip][dst_port].append(current_time)
            
            # Clean old entries
            for port in list(self.connections[src_ip].keys()):
                self.connections[src_ip][port] = [
                    t for t in self.connections[src_ip][port] 
                    if current_time - t <= self.time_window
                ]
            
            # Check if threshold exceeded
            unique_ports = len([p for p in self.connections[src_ip] if self.connections[src_ip][p]])
            if unique_ports >= self.threshold:
                return f"🔭 Port Scan Detected from {src_ip} - {unique_ports} ports scanned"
        return None

def start_port_scan_detection(interface=None):
    detector = PortScanDetector()
    
    def packet_handler(packet):
        alert = detector.detect_scan(packet)
        if alert:
            print(alert)
    
    sniff(iface=interface, prn=packet_handler, filter="tcp")

if __name__ == "__main__":
    start_port_scan_detection()
