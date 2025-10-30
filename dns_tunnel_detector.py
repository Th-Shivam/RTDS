#!/usr/bin/env python3

import time
import re
import base64
import math
import hashlib
from collections import defaultdict, deque, Counter
from scapy.all import DNS, DNSQR, DNSRR, IP
import logging

class AdvancedDNSTunnelDetector:
    def __init__(self, 
                 query_threshold=50,
                 subdomain_threshold=10,
                 length_threshold=50,
                 entropy_threshold=4.5,
                 response_size_threshold=512,
                 burst_threshold=20):
        
        self.query_threshold = query_threshold
        self.subdomain_threshold = subdomain_threshold
        self.length_threshold = length_threshold
        self.entropy_threshold = entropy_threshold
        self.response_size_threshold = response_size_threshold
        self.burst_threshold = burst_threshold
        
        # Enhanced tracking
        self.domain_queries = defaultdict(lambda: deque(maxlen=200))
        self.subdomain_count = defaultdict(set)
        self.suspicious_domains = set()
        self.query_types = defaultdict(lambda: defaultdict(int))
        self.response_sizes = defaultdict(list)
        self.client_patterns = defaultdict(lambda: defaultdict(int))
        self.dns_sessions = defaultdict(lambda: {'start': 0, 'queries': 0, 'data_volume': 0})
        
        # ML-like features
        self.domain_features = defaultdict(lambda: {
            'avg_entropy': 0, 'max_length': 0, 'unique_chars': set(),
            'numeric_ratio': 0, 'consonant_ratio': 0, 'pattern_score': 0
        })
        
        # Whitelist common domains
        self.whitelist = {
            'google.com', 'microsoft.com', 'amazon.com', 'cloudflare.com',
            'googleapis.com', 'windows.com', 'office.com', 'live.com'
        }
        
        logging.basicConfig(filename='dns_tunnel_alerts.log', level=logging.INFO,
                          format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    
    def calculate_entropy(self, data):
        """Enhanced Shannon entropy calculation"""
        if not data or len(data) < 2:
            return 0
        
        counts = Counter(data)
        entropy = 0
        for count in counts.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy
    
    def analyze_character_patterns(self, string):
        """Advanced character pattern analysis"""
        if not string:
            return {'numeric_ratio': 0, 'consonant_ratio': 0, 'pattern_score': 0}
        
        numeric_count = sum(1 for c in string if c.isdigit())
        consonants = 'bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ'
        consonant_count = sum(1 for c in string if c in consonants)
        
        # Pattern scoring
        pattern_score = 0
        if re.search(r'[0-9]{4,}', string): pattern_score += 2  # Long numbers
        if re.search(r'[a-f0-9]{8,}', string): pattern_score += 3  # Hex patterns
        if re.search(r'[A-Za-z0-9+/]{10,}={0,2}', string): pattern_score += 4  # Base64
        if len(set(string)) / len(string) > 0.8: pattern_score += 2  # High uniqueness
        
        return {
            'numeric_ratio': numeric_count / len(string),
            'consonant_ratio': consonant_count / len(string),
            'pattern_score': pattern_score
        }
    
    def detect_encoding_schemes(self, subdomain):
        """Detect various encoding schemes"""
        encodings = []
        
        # Base64 detection
        if re.match(r'^[A-Za-z0-9+/]{4,}={0,2}$', subdomain):
            try:
                decoded = base64.b64decode(subdomain + '==')
                if all(32 <= b <= 126 for b in decoded[:10]):  # Printable ASCII
                    encodings.append('base64')
            except: pass
        
        # Hex encoding
        if re.match(r'^[a-f0-9]+$', subdomain) and len(subdomain) % 2 == 0:
            try:
                decoded = bytes.fromhex(subdomain)
                if all(32 <= b <= 126 for b in decoded[:10]):
                    encodings.append('hex')
            except: pass
        
        # Base32 detection
        if re.match(r'^[A-Z2-7]+=*$', subdomain.upper()):
            encodings.append('base32')
        
        return encodings
    
    def analyze_dns_session(self, src_ip, domain, query_size):
        """Track DNS session patterns"""
        current_time = time.time()
        session = self.dns_sessions[f"{src_ip}:{domain}"]
        
        if session['start'] == 0:
            session['start'] = current_time
        
        session['queries'] += 1
        session['data_volume'] += query_size
        
        # Session-based anomalies
        session_duration = current_time - session['start']
        if session_duration > 0:
            qps = session['queries'] / session_duration
            if qps > 10:  # High query rate
                return f"High query rate: {qps:.1f} qps"
        
        if session['data_volume'] > 10000:  # Large data transfer
            return f"Large data volume: {session['data_volume']} bytes"
        
        return None
    
    def analyze_query_pattern(self, query_name, src_ip, query_type='A'):
        """Enhanced DNS query analysis with ML-like features"""
        alerts = []
        parts = query_name.lower().split('.')
        if len(parts) < 2:
            return alerts
        
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else parts[0]
        domain = '.'.join(parts[-2:])
        current_time = time.time()
        
        # Skip whitelisted domains
        if domain in self.whitelist:
            return alerts
        
        # 1. Enhanced frequency analysis with burst detection
        self.domain_queries[domain].append(current_time)
        recent_queries = [t for t in self.domain_queries[domain] if current_time - t < 60]
        
        if len(recent_queries) > self.query_threshold:
            alerts.append(f"High DNS frequency: {domain} ({len(recent_queries)} queries/min)")
        
        # Burst detection (many queries in short time)
        burst_queries = [t for t in self.domain_queries[domain] if current_time - t < 5]
        if len(burst_queries) > self.burst_threshold:
            alerts.append(f"DNS query burst: {domain} ({len(burst_queries)} queries in 5s)")
        
        # 2. Advanced subdomain analysis
        if subdomain:
            self.subdomain_count[domain].add(subdomain)
            if len(self.subdomain_count[domain]) > self.subdomain_threshold:
                alerts.append(f"Excessive subdomains: {domain} ({len(self.subdomain_count[domain])} unique)")
            
            # Character pattern analysis
            patterns = self.analyze_character_patterns(subdomain)
            if patterns['numeric_ratio'] > 0.7:
                alerts.append(f"High numeric content: {subdomain[:30]}... ({patterns['numeric_ratio']:.2f})")
            
            if patterns['pattern_score'] > 5:
                alerts.append(f"Suspicious encoding pattern: {subdomain[:30]}... (score: {patterns['pattern_score']})")
        
        # 3. Enhanced entropy analysis
        if subdomain and len(subdomain) > 8:
            entropy = self.calculate_entropy(subdomain)
            if entropy > self.entropy_threshold:
                alerts.append(f"High entropy subdomain: {subdomain[:30]}... (entropy: {entropy:.2f})")
            
            # Update domain features
            features = self.domain_features[domain]
            features['avg_entropy'] = (features['avg_entropy'] + entropy) / 2
            features['max_length'] = max(features['max_length'], len(subdomain))
            features['unique_chars'].update(set(subdomain))
        
        # 4. Encoding detection
        if subdomain:
            encodings = self.detect_encoding_schemes(subdomain)
            if encodings:
                alerts.append(f"Encoded subdomain detected ({','.join(encodings)}): {subdomain[:30]}...")
        
        # 5. Query type analysis
        self.query_types[domain][query_type] += 1
        if len(self.query_types[domain]) > 5:  # Multiple query types
            alerts.append(f"Multiple DNS query types: {domain} ({list(self.query_types[domain].keys())})")
        
        # 6. Session analysis
        session_alert = self.analyze_dns_session(src_ip, domain, len(query_name))
        if session_alert:
            alerts.append(session_alert)
        
        # 7. Client behavior analysis
        self.client_patterns[src_ip][domain] += 1
        if len(self.client_patterns[src_ip]) > 20:  # Client querying many domains
            alerts.append(f"Client querying many domains: {src_ip} ({len(self.client_patterns[src_ip])} domains)")
        
        return alerts
    
    def detect_tunnel(self, packet):
        """Enhanced DNS tunnel detection with response analysis"""
        if not packet.haslayer(DNS):
            return []
        
        dns_layer = packet[DNS]
        alerts = []
        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        
        # Analyze DNS queries
        if dns_layer.qr == 0 and hasattr(dns_layer, 'qd') and dns_layer.qd:
            try:
                query = dns_layer.qd
                query_name = query.qname.decode('utf-8').rstrip('.')
                query_type = query.qtype
                
                # Convert query type number to string
                qtype_map = {1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT', 12: 'PTR'}
                qtype_str = qtype_map.get(query_type, str(query_type))
                
                query_alerts = self.analyze_query_pattern(query_name, src_ip, qtype_str)
                for alert in query_alerts:
                    full_alert = f"DNS Tunnel Detected from {src_ip}: {alert}"
                    alerts.append(full_alert)
                    self.logger.warning(full_alert)
                    
            except Exception as e:
                pass
        
        # Analyze DNS responses
        elif dns_layer.qr == 1 and hasattr(dns_layer, 'an') and dns_layer.an:
            try:
                response_size = len(packet)
                if response_size > self.response_size_threshold:
                    alert = f"Large DNS response: {response_size} bytes from {src_ip}"
                    alerts.append(alert)
                    self.logger.warning(alert)
                
                # Analyze TXT record responses (common for tunneling)
                if dns_layer.ancount > 0:
                    for i in range(dns_layer.ancount):
                        rr = dns_layer.an[i] if hasattr(dns_layer.an, '__getitem__') else dns_layer.an
                        if hasattr(rr, 'type') and rr.type == 16:  # TXT record
                            if hasattr(rr, 'rdata') and len(rr.rdata) > 100:
                                alert = f"Large TXT record response: {len(rr.rdata)} bytes"
                                alerts.append(alert)
                                self.logger.warning(alert)
                                
            except Exception as e:
                pass
        
        return alerts
    
    def get_advanced_statistics(self):
        """Enhanced statistics with ML-like features"""
        current_time = time.time()
        active_domains = 0
        high_entropy_domains = 0
        
        for domain, features in self.domain_features.items():
            if features['avg_entropy'] > self.entropy_threshold:
                high_entropy_domains += 1
            
            # Check if domain had recent activity
            recent_activity = [t for t in self.domain_queries[domain] if current_time - t < 300]
            if recent_activity:
                active_domains += 1
        
        return {
            'monitored_domains': len(self.domain_queries),
            'active_domains': active_domains,
            'high_entropy_domains': high_entropy_domains,
            'total_subdomains': sum(len(subs) for subs in self.subdomain_count.values()),
            'suspicious_domains': len(self.suspicious_domains),
            'active_clients': len(self.client_patterns),
            'total_sessions': len(self.dns_sessions)
        }

# Integration function for main RTDS
def integrate_dns_detection(packet_handler_func):
    """Integrate enhanced DNS tunnel detection"""
    dns_detector = AdvancedDNSTunnelDetector()
    
    def enhanced_packet_handler(packet):
        existing_alerts = packet_handler_func(packet)
        dns_alerts = dns_detector.detect_tunnel(packet)
        return existing_alerts + dns_alerts
    
    return enhanced_packet_handler

if __name__ == "__main__":
    from scapy.all import sniff
    
    detector = AdvancedDNSTunnelDetector()
    
    def packet_handler(packet):
        alerts = detector.detect_tunnel(packet)
        for alert in alerts:
            print(f"[{time.strftime('%H:%M:%S')}] 🚨 {alert}")
    
    print("🔍 Advanced DNS Tunnel Detector Started")
    print("Enhanced Features:")
    print("  ✓ ML-like pattern analysis")
    print("  ✓ Multi-encoding detection")
    print("  ✓ Session tracking")
    print("  ✓ Response analysis")
    print("  ✓ Burst detection")
    
    try:
        sniff(filter="udp port 53", prn=packet_handler)
    except KeyboardInterrupt:
        print("\n📊 Advanced Detection Statistics:")
        stats = detector.get_advanced_statistics()
        for key, value in stats.items():
            print(f"  {key}: {value}")
