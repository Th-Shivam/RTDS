#!/usr/bin/env python3
from scapy.all import *
from collections import defaultdict
import time
import json
import logging

class EnhancedPortScanDetector:
    def __init__(self, threshold=20, time_window=60, stealth_threshold=5):
        self.threshold = threshold
        self.stealth_threshold = stealth_threshold
        self.time_window = time_window
        self.connections = defaultdict(lambda: defaultdict(list))
        self.scan_patterns = defaultdict(lambda: {'syn': 0, 'fin': 0, 'null': 0, 'xmas': 0})
        self.blocked_ips = set()
        
        # Setup logging
        logging.basicConfig(filename='port_scan_alerts.log', level=logging.INFO,
                          format='%(asctime)s - %(message)s')
    
    def detect_scan_type(self, packet):
        """Detect different types of port scans"""
        if not packet.haslayer(TCP):
            return None
            
        tcp_flags = packet[TCP].flags
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()
        
        # Track connection attempts
        self.connections[src_ip][dst_port].append(current_time)
        
        # Analyze scan patterns
        if tcp_flags == 2:  # SYN scan
            self.scan_patterns[src_ip]['syn'] += 1
        elif tcp_flags == 1:  # FIN scan
            self.scan_patterns[src_ip]['fin'] += 1
        elif tcp_flags == 0:  # NULL scan
            self.scan_patterns[src_ip]['null'] += 1
        elif tcp_flags == 41:  # XMAS scan (FIN+PSH+URG)
            self.scan_patterns[src_ip]['xmas'] += 1
        
        # Clean old entries
        self._cleanup_old_entries(src_ip, current_time)
        
        # Check for various scan types
        return self._analyze_scan_behavior(src_ip, current_time)
    
    def _cleanup_old_entries(self, src_ip, current_time):
        """Remove old connection records"""
        for port in list(self.connections[src_ip].keys()):
            self.connections[src_ip][port] = [
                t for t in self.connections[src_ip][port] 
                if current_time - t <= self.time_window
            ]
            if not self.connections[src_ip][port]:
                del self.connections[src_ip][port]
    
    def _analyze_scan_behavior(self, src_ip, current_time):
        """Analyze scanning behavior and return alert"""
        unique_ports = len(self.connections[src_ip])
        patterns = self.scan_patterns[src_ip]
        
        alerts = []
        
        # Aggressive port scan
        if unique_ports >= self.threshold:
            scan_rate = unique_ports / self.time_window
            alert = f"🚨 AGGRESSIVE Port Scan: {src_ip} → {unique_ports} ports ({scan_rate:.1f}/sec)"
            alerts.append(alert)
            self._log_alert(alert, src_ip, "AGGRESSIVE_SCAN")
        
        # Stealth scan detection
        elif unique_ports >= self.stealth_threshold:
            if patterns['fin'] > patterns['syn']:
                alert = f"🥷 STEALTH FIN Scan: {src_ip} → {unique_ports} ports"
                alerts.append(alert)
                self._log_alert(alert, src_ip, "FIN_SCAN")
            elif patterns['null'] > 0:
                alert = f"🥷 STEALTH NULL Scan: {src_ip} → {unique_ports} ports"
                alerts.append(alert)
                self._log_alert(alert, src_ip, "NULL_SCAN")
            elif patterns['xmas'] > 0:
                alert = f"🎄 XMAS Scan: {src_ip} → {unique_ports} ports"
                alerts.append(alert)
                self._log_alert(alert, src_ip, "XMAS_SCAN")
        
        # Sequential port scanning
        if unique_ports >= 10:
            ports = sorted([int(p) for p in self.connections[src_ip].keys()])
            if self._is_sequential(ports):
                alert = f"📊 SEQUENTIAL Scan: {src_ip} → ports {ports[0]}-{ports[-1]}"
                alerts.append(alert)
                self._log_alert(alert, src_ip, "SEQUENTIAL_SCAN")
        
        return alerts if alerts else None
    
    def _is_sequential(self, ports):
        """Check if ports are being scanned sequentially"""
        if len(ports) < 5:
            return False
        sequential_count = 0
        for i in range(1, len(ports)):
            if ports[i] - ports[i-1] == 1:
                sequential_count += 1
        return sequential_count / len(ports) > 0.7
    
    def _log_alert(self, alert, src_ip, scan_type):
        """Log alert to file and optionally block IP"""
        log_entry = {
            'timestamp': time.time(),
            'source_ip': src_ip,
            'scan_type': scan_type,
            'alert': alert,
            'ports_scanned': len(self.connections[src_ip])
        }
        logging.info(json.dumps(log_entry))
        
        # Auto-block aggressive scanners
        if scan_type == "AGGRESSIVE_SCAN" and src_ip not in self.blocked_ips:
            self.blocked_ips.add(src_ip)
            print(f"🚫 AUTO-BLOCKED: {src_ip}")
    
    def get_scan_stats(self):
        """Return current scanning statistics"""
        total_scanners = len(self.connections)
        total_blocked = len(self.blocked_ips)
        active_scans = sum(len(ports) for ports in self.connections.values())
        
        return {
            'active_scanners': total_scanners,
            'blocked_ips': total_blocked,
            'total_scan_attempts': active_scans
        }

def start_enhanced_port_detection(interface=None, threshold=20, stealth_threshold=5):
    """Start enhanced port scan detection with real-time monitoring"""
    detector = EnhancedPortScanDetector(threshold, stealth_threshold=stealth_threshold)
    
    print("🔭 Enhanced Port Scan Detection Started")
    print(f"📊 Threshold: {threshold} ports | Stealth: {stealth_threshold} ports")
    print("=" * 60)
    
    def packet_handler(packet):
        alerts = detector.detect_scan_type(packet)
        if alerts:
            for alert in alerts:
                print(f"[{time.strftime('%H:%M:%S')}] {alert}")
    
    def show_stats():
        """Display periodic statistics"""
        while True:
            time.sleep(30)  # Show stats every 30 seconds
            stats = detector.get_scan_stats()
            print(f"\n📈 Stats: {stats['active_scanners']} scanners | "
                  f"{stats['blocked_ips']} blocked | "
                  f"{stats['total_scan_attempts']} attempts\n")
    
    # Start stats thread
    import threading
    stats_thread = threading.Thread(target=show_stats, daemon=True)
    stats_thread.start()
    
    try:
        sniff(iface=interface, prn=packet_handler, filter="tcp", store=0)
    except KeyboardInterrupt:
        print("\n🛑 Port scan detection stopped")
        final_stats = detector.get_scan_stats()
        print(f"Final Stats: {json.dumps(final_stats, indent=2)}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Enhanced Port Scan Detector')
    parser.add_argument('--interface', '-i', help='Network interface to monitor')
    parser.add_argument('--threshold', '-t', type=int, default=20, help='Port scan threshold')
    parser.add_argument('--stealth', '-s', type=int, default=5, help='Stealth scan threshold')
    
    args = parser.parse_args()
    start_enhanced_port_detection(args.interface, args.threshold, args.stealth)
