#!/usr/bin/env python3
import re
import json
import time
import logging
from urllib.parse import urlparse
from scapy.all import *

class RTDSPhishingModule:
    def __init__(self, log_file="logs/phishing_alerts.log"):
        self.suspicious_domains = set()
        self.alert_count = 0
        self.setup_logging(log_file)
        
        # Enhanced detection patterns
        self.patterns = {
            'phishing_keywords': [
                'verify-account', 'suspended-account', 'urgent-action', 'click-here',
                'secure-login', 'update-payment', 'confirm-identity', 'account-locked'
            ],
            'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf', '.bit', '.onion'],
            'legitimate_spoofs': {
                'paypal': ['paypal', 'payp4l', 'paypaI', 'payp-al'],
                'amazon': ['amazon', 'amaz0n', 'amazom', 'amaz-on'],
                'microsoft': ['microsoft', 'micr0soft', 'micro-soft'],
                'google': ['google', 'g00gle', 'googIe', 'goog-le']
            }
        }
    
    def setup_logging(self, log_file):
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - PHISHING - %(message)s'
        )
        self.logger = logging.getLogger('RTDS_Phishing')
    
    def detect_homograph_attack(self, domain):
        # Check for mixed scripts or suspicious unicode
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у']  # Cyrillic lookalikes
        for char in suspicious_chars:
            if char in domain:
                return True
        return False
    
    def check_domain_spoofing(self, domain):
        for brand, variants in self.patterns['legitimate_spoofs'].items():
            for variant in variants:
                if variant in domain and domain != f"{brand}.com":
                    return brand
        return None
    
    def analyze_url_structure(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            risk_score = 0
            alerts = []
            
            # Domain analysis
            if len(domain) > 40:
                risk_score += 15
                alerts.append("Unusually long domain")
            
            if domain.count('.') > 4:
                risk_score += 20
                alerts.append("Excessive subdomains")
            
            if domain.count('-') > 3:
                risk_score += 15
                alerts.append("Multiple hyphens")
            
            # Check for suspicious TLD
            for tld in self.patterns['suspicious_tlds']:
                if domain.endswith(tld):
                    risk_score += 30
                    alerts.append(f"Suspicious TLD: {tld}")
            
            # Check for phishing keywords
            full_url = f"{domain}{path}"
            for keyword in self.patterns['phishing_keywords']:
                if keyword in full_url:
                    risk_score += 25
                    alerts.append(f"Phishing keyword: {keyword}")
            
            # Check for homograph attacks
            if self.detect_homograph_attack(domain):
                risk_score += 35
                alerts.append("Possible homograph attack")
            
            # Check for brand spoofing
            spoofed_brand = self.check_domain_spoofing(domain)
            if spoofed_brand:
                risk_score += 40
                alerts.append(f"Possible {spoofed_brand} spoofing")
            
            return risk_score, alerts
            
        except Exception:
            return 0, []
    
    def extract_urls(self, packet):
        urls = []
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                # Multiple URL extraction patterns
                patterns = [
                    r'https?://[^\s<>"{}|\\^`\[\]]+',
                    r'(?:Host|Referer|Location):\s*([^\r\n]+)',
                    r'href=["\']([^"\']+)["\']',
                    r'src=["\']([^"\']+)["\']'
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, payload, re.IGNORECASE)
                    for match in matches:
                        if match.startswith(('http://', 'https://')):
                            urls.append(match)
                        elif '.' in match and not match.startswith('/'):
                            urls.append(f"http://{match}")
            except:
                pass
        return list(set(urls))  # Remove duplicates
    
    def process_packet(self, packet):
        urls = self.extract_urls(packet)
        alerts = []
        
        for url in urls:
            if url not in self.suspicious_domains:
                risk_score, url_alerts = self.analyze_url_structure(url)
                
                if risk_score >= 30:  # Threshold for phishing alert
                    self.suspicious_domains.add(url)
                    self.alert_count += 1
                    
                    alert_msg = {
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'url': url,
                        'risk_score': risk_score,
                        'alerts': url_alerts,
                        'source_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown'
                    }
                    
                    alerts.append(alert_msg)
                    self.logger.info(f"Phishing detected: {json.dumps(alert_msg)}")
        
        return alerts
    
    def get_stats(self):
        return {
            'total_alerts': self.alert_count,
            'suspicious_domains': len(self.suspicious_domains),
            'last_check': time.strftime('%Y-%m-%d %H:%M:%S')
        }

# Integration function for main RTDS
def integrate_phishing_detection(rtds_instance):
    phishing_module = RTDSPhishingModule()
    
    def enhanced_packet_handler(packet):
        # Run existing RTDS detection
        rtds_instance.original_packet_handler(packet)
        
        # Add phishing detection
        phishing_alerts = phishing_module.process_packet(packet)
        for alert in phishing_alerts:
            print(f"\n🎣 PHISHING ALERT (Score: {alert['risk_score']})")
            print(f"URL: {alert['url']}")
            print(f"Source: {alert['source_ip']}")
            for detail in alert['alerts']:
                print(f"  • {detail}")
            print("-" * 60)
    
    return enhanced_packet_handler, phishing_module

if __name__ == "__main__":
    # Standalone mode
    detector = RTDSPhishingModule()
    print("🎣 RTDS Phishing Module - Standalone Mode")
    
    def packet_handler(packet):
        alerts = detector.process_packet(packet)
        for alert in alerts:
            print(f"\n🚨 PHISHING DETECTED (Risk: {alert['risk_score']})")
            print(f"URL: {alert['url']}")
            for detail in alert['alerts']:
                print(f"  • {detail}")
    
    try:
        sniff(prn=packet_handler, filter="tcp port 80 or tcp port 443")
    except KeyboardInterrupt:
        stats = detector.get_stats()
        print(f"\n📊 Final Stats: {stats}")
