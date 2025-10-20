#!/usr/bin/env python3

import time
import re
import base64
from collections import defaultdict, deque
from scapy.all import DNS, DNSQR, DNSRR, IP
import logging

class DNSTunnelDetector:
    def __init__(self, 
                 query_threshold=50,      # Max queries per minute per domain
                 subdomain_threshold=10,   # Max subdomains per domain
                 length_threshold=50,      # Suspicious query length
                 entropy_threshold=4.5):   # High entropy indicates encoding
        
        self.query_threshold = query_threshold
        self.subdomain_threshold = subdomain_threshold
        self.length_threshold = length_threshold
        self.entropy_threshold = entropy_threshold
        
        # Tracking data structures
        self.domain_queries = defaultdict(lambda: deque(maxlen=100))
        self.subdomain_count = defaultdict(set)
        self.suspicious_domains = set()
        
        # Setup logging
        logging.basicConfig(filename='dns_tunnel_alerts.log', level=logging.INFO,
                          format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of string"""
        if not data:
            return 0
        
        import math
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy
    
    def is_base64_encoded(self, string):
        """Check if string appears to be base64 encoded"""
        try:
            if len(string) % 4 == 0:
                base64.b64decode(string, validate=True)
                return True
        except:
            pass
        return False
    
    def analyze_query_pattern(self, query_name):
        """Analyze DNS query for tunneling patterns"""
        alerts = []
        
        # Extract domain parts
        parts = query_name.lower().split('.')
        if len(parts) < 2:
            return alerts
        
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else parts[0]
        domain = '.'.join(parts[-2:])
        
        current_time = time.time()
        
        # 1. Query frequency analysis
        self.domain_queries[domain].append(current_time)
        recent_queries = [t for t in self.domain_queries[domain] if current_time - t < 60]
        
        if len(recent_queries) > self.query_threshold:
            alerts.append(f"High DNS query frequency: {domain} ({len(recent_queries)} queries/min)")
        
        # 2. Subdomain analysis
        if subdomain:
            self.subdomain_count[domain].add(subdomain)
            if len(self.subdomain_count[domain]) > self.subdomain_threshold:
                alerts.append(f"Excessive subdomains: {domain} ({len(self.subdomain_count[domain])} unique)")
        
        # 3. Query length analysis
        if len(query_name) > self.length_threshold:
            alerts.append(f"Suspicious query length: {query_name[:50]}... ({len(query_name)} chars)")
        
        # 4. Entropy analysis (data encoding detection)
        if subdomain:
            entropy = self.calculate_entropy(subdomain)
            if entropy > self.entropy_threshold:
                alerts.append(f"High entropy subdomain: {subdomain[:30]}... (entropy: {entropy:.2f})")
        
        # 5. Base64 encoding detection
        if subdomain and len(subdomain) > 10 and self.is_base64_encoded(subdomain):
            alerts.append(f"Base64 encoded subdomain detected: {subdomain[:30]}...")
        
        # 6. Suspicious patterns
        suspicious_patterns = [
            r'^[a-f0-9]{20,}',  # Long hex strings
            r'^[A-Za-z0-9+/]{20,}={0,2}$',  # Base64 pattern
            r'^\d+\.',  # Numeric prefixes
        ]
        
        for pattern in suspicious_patterns:
            if subdomain and re.match(pattern, subdomain):
                alerts.append(f"Suspicious pattern in subdomain: {subdomain[:30]}...")
        
        return alerts
    
    def detect_tunnel(self, packet):
        """Main detection function for DNS packets"""
        if not packet.haslayer(DNS):
            return []
        
        dns_layer = packet[DNS]
        alerts = []
        
        # Analyze DNS queries
        if dns_layer.qr == 0 and hasattr(dns_layer, 'qd') and dns_layer.qd:  # DNS query
            try:
                query = dns_layer.qd
                query_name = query.qname.decode('utf-8').rstrip('.')
                
                query_alerts = self.analyze_query_pattern(query_name)
                for alert in query_alerts:
                    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                    full_alert = f"DNS Tunnel Detected from {src_ip}: {alert}"
                    alerts.append(full_alert)
                    self.logger.warning(full_alert)
            except Exception as e:
                pass  # Skip malformed packets
        
        return alerts
    
    def get_statistics(self):
        """Get current detection statistics"""
        total_domains = len(self.domain_queries)
        total_subdomains = sum(len(subs) for subs in self.subdomain_count.values())
        
        return {
            'monitored_domains': total_domains,
            'total_subdomains': total_subdomains,
            'suspicious_domains': len(self.suspicious_domains),
            'active_queries': sum(len(queries) for queries in self.domain_queries.values())
        }

# Integration function for main RTDS
def integrate_dns_detection(packet_handler_func):
    """Integrate DNS tunnel detection with existing packet handler"""
    dns_detector = DNSTunnelDetector()
    
    def enhanced_packet_handler(packet):
        # Run existing detection
        existing_alerts = packet_handler_func(packet)
        
        # Add DNS tunnel detection
        dns_alerts = dns_detector.detect_tunnel(packet)
        
        # Combine alerts
        all_alerts = existing_alerts + dns_alerts
        return all_alerts
    
    return enhanced_packet_handler

if __name__ == "__main__":
    from scapy.all import sniff
    
    detector = DNSTunnelDetector()
    
    def packet_handler(packet):
        alerts = detector.detect_tunnel(packet)
        for alert in alerts:
            print(f"[{time.strftime('%H:%M:%S')}] 🚨 {alert}")
    
    print("🔍 DNS Tunnel Detector Started")
    print("Monitoring for DNS tunneling activities...")
    
    try:
        sniff(filter="udp port 53", prn=packet_handler)
    except KeyboardInterrupt:
        print("\n📊 Detection Statistics:")
        stats = detector.get_statistics()
        for key, value in stats.items():
            print(f"  {key}: {value}")
