#!/usr/bin/env python3
import requests
import re
import socket
import ssl
import threading
from urllib.parse import urlparse
from scapy.all import *
import time

class AdvancedPhishingDetector:
    def __init__(self, vt_api_key=None):
        self.api_key = vt_api_key
        self.suspicious_domains = set()
        self.legitimate_domains = {'google.com', 'facebook.com', 'amazon.com', 'microsoft.com'}
        self.phishing_indicators = {
            'keywords': ['verify', 'suspended', 'urgent', 'click-here', 'secure-login'],
            'suspicious_chars': ['-', '_', '0', '1'],
            'tlds': ['.tk', '.ml', '.ga', '.cf', '.bit']
        }
        
    def check_domain_age(self, domain):
        try:
            import whois
            w = whois.whois(domain)
            if w.creation_date:
                age = (time.time() - w.creation_date.timestamp()) / (365 * 24 * 3600)
                return age < 30  # Domain less than 30 days old
        except:
            pass
        return False
    
    def check_ssl_cert(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    # Check if cert is self-signed or has suspicious issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    return issuer.get('organizationName') == subject.get('organizationName')
        except:
            return True  # Assume suspicious if can't verify
    
    def analyze_url(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            score = 0
            alerts = []
            
            # Check for suspicious TLD
            for tld in self.phishing_indicators['tlds']:
                if domain.endswith(tld):
                    score += 30
                    alerts.append(f"Suspicious TLD: {tld}")
            
            # Check for phishing keywords
            for keyword in self.phishing_indicators['keywords']:
                if keyword in domain or keyword in parsed.path:
                    score += 20
                    alerts.append(f"Phishing keyword: {keyword}")
            
            # Check for domain spoofing
            for legit in self.legitimate_domains:
                if legit in domain and domain != legit:
                    score += 40
                    alerts.append(f"Possible spoofing of {legit}")
            
            # Check domain length and complexity
            if len(domain) > 30:
                score += 10
                alerts.append("Unusually long domain")
            
            if domain.count('-') > 2:
                score += 15
                alerts.append("Multiple hyphens in domain")
            
            # Check for new domain
            if self.check_domain_age(domain):
                score += 25
                alerts.append("Recently registered domain")
            
            # Check SSL certificate
            if self.check_ssl_cert(domain):
                score += 20
                alerts.append("Suspicious SSL certificate")
            
            return score, alerts
            
        except Exception as e:
            return 0, []
    
    def extract_urls_from_packet(self, packet):
        urls = []
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                patterns = [
                    r'https?://[^\s<>"{}|\\^`\[\]]+',
                    r'(?:Host|Referer):\s*([^\r\n]+)',
                    r'Location:\s*([^\r\n]+)'
                ]
                for pattern in patterns:
                    matches = re.findall(pattern, payload, re.IGNORECASE)
                    urls.extend(matches)
            except:
                pass
        return urls
    
    def monitor_traffic(self, interface=None):
        print("🎣 Advanced Phishing Detector Started")
        print(f"Interface: {interface or 'All interfaces'}")
        
        def packet_handler(packet):
            urls = self.extract_urls_from_packet(packet)
            for url in urls:
                if url not in self.suspicious_domains:
                    score, alerts = self.analyze_url(url)
                    if score > 30:  # Threshold for suspicious
                        self.suspicious_domains.add(url)
                        print(f"\n🚨 PHISHING ALERT (Score: {score})")
                        print(f"URL: {url}")
                        for alert in alerts:
                            print(f"  • {alert}")
                        print("-" * 50)
        
        sniff(iface=interface, prn=packet_handler, filter="tcp port 80 or tcp port 443")

def main():
    detector = AdvancedPhishingDetector()
    try:
        detector.monitor_traffic()
    except KeyboardInterrupt:
        print("\n🛑 Phishing detector stopped")

if __name__ == "__main__":
    main()
