#!/usr/bin/env python3
import requests
import re
import json
import hashlib
from urllib.parse import urlparse
from scapy.all import *

class EnhancedPhishingDetector:
    def __init__(self, vt_api_key=None):
        self.api_key = vt_api_key
        self.vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
        self.suspicious_domains = set()
        self.phishing_keywords = [
            'login', 'verify', 'account', 'suspended', 'urgent', 'click', 'secure',
            'paypal', 'amazon', 'microsoft', 'google', 'apple', 'bank', 'update'
        ]
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit', '.onion']
        
    def extract_urls(self, packet):
        urls = []
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # Enhanced URL extraction
            patterns = [
                r'http[s]?://[^\s<>"{}|\\^`\[\]]+',
                r'(?:Host:|Referer:)\s*([^\r\n]+)',
                r'Location:\s*([^\r\n]+)'
            ]
            for pattern in patterns:
                urls.extend(re.findall(pattern, payload, re.IGNORECASE))
        return urls
    
    def check_suspicious_domain(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for suspicious TLDs
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    return f"🚨 Suspicious TLD: {url}"
            
            # Check for phishing keywords in domain
            for keyword in self.phishing_keywords:
                if keyword in domain:
                    return f"⚠️ Suspicious keyword in domain: {url}"
            
            # Check for homograph attacks (basic)
            if any(ord(c) > 127 for c in domain):
                return f"🔤 Possible homograph attack: {url}"
                
            # Check for excessive subdomains
            if domain.count('.') > 3:
                return f"🌐 Excessive subdomains: {url}"
                
        except:
            pass
        return None
    
    def check_url_vt(self, url):
        if not self.api_key:
            return None
        params = {'apikey': self.api_key, 'resource': url}
        try:
            response = requests.get(self.vt_url, params=params, timeout=5)
            result = response.json()
            if result.get('response_code') == 1 and result.get('positives', 0) > 0:
                return f"🎣 VT Detection: {url} ({result['positives']}/{result['total']})"
        except:
            pass
        return None
    
    def analyze_packet(self, packet):
        urls = self.extract_urls(packet)
        alerts = []
        
        for url in urls:
            if url not in self.suspicious_domains:
                # Local checks (fast)
                alert = self.check_suspicious_domain(url)
                if alert:
                    alerts.append(alert)
                    self.suspicious_domains.add(url)
                
                # VirusTotal check (slower)
                elif self.api_key:
                    vt_alert = self.check_url_vt(url)
                    if vt_alert:
                        alerts.append(vt_alert)
                        self.suspicious_domains.add(url)
        
        return alerts

def start_phishing_detection(api_key=None, interface=None):
    detector = EnhancedPhishingDetector(api_key)
    print("🎣 Enhanced Phishing Detector Started")
    print(f"Interface: {interface or 'All'}")
    print(f"VirusTotal: {'Enabled' if api_key else 'Disabled'}")
    
    def packet_handler(packet):
        alerts = detector.analyze_packet(packet)
        for alert in alerts:
            print(alert)
    
    sniff(iface=interface, prn=packet_handler, filter="tcp port 80 or tcp port 443")

if __name__ == "__main__":
    API_KEY = None  # Set your VirusTotal API key here
    start_phishing_detection(API_KEY)
