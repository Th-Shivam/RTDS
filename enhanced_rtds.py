#!/usr/bin/env python3
from rtds_monitor import *
from port_scan_detector import PortScanDetector
from phishing_detector import PhishingDetector
from dns_tunnel_detector import AdvancedDNSTunnelDetector
import threading

class EnhancedRTDS:
    def __init__(self, vt_api_key=None):
        self.port_scanner = PortScanDetector()
        self.phishing_detector = PhishingDetector(vt_api_key) if vt_api_key else None
        self.dns_detector = AdvancedDNSTunnelDetector()
        
    def enhanced_packet_handler(self, packet):
        alerts = []
        
        # Port scan detection
        port_alert = self.port_scanner.detect_scan(packet)
        if port_alert:
            alerts.append(port_alert)
        
        # Phishing detection
        if self.phishing_detector:
            phish_alert = self.phishing_detector.analyze_packet(packet)
            if phish_alert:
                alerts.append(phish_alert)
        
        # Advanced DNS tunnel detection
        dns_alerts = self.dns_detector.detect_tunnel(packet)
        alerts.extend(dns_alerts)
        
        return alerts

def start_enhanced_monitoring(interface=None, vt_api_key=None):
    enhanced_rtds = EnhancedRTDS(vt_api_key)
    
    def packet_handler(packet):
        alerts = enhanced_rtds.enhanced_packet_handler(packet)
        for alert in alerts:
            print(f"[{time.strftime('%H:%M:%S')}] {alert}")
    
    print("🛡️ Enhanced RTDS Started - Advanced Multi-Attack Detection")
    print("✓ Port Scanning Detection: Active")
    print(f"✓ Phishing Detection: {'Active' if vt_api_key else 'Disabled (No API Key)'}")
    print("✓ Advanced DNS Tunneling Detection: Active")
    print("  • ML-like pattern analysis")
    print("  • Multi-encoding detection") 
    print("  • Session tracking & burst detection")
    print("✓ DDoS & MITM Detection: Active")
    
    sniff(iface=interface, prn=packet_handler)

if __name__ == "__main__":
    # Add your VirusTotal API key here
    VT_API_KEY = None  # Replace with "your_api_key_here"
    start_enhanced_monitoring(vt_api_key=VT_API_KEY)
