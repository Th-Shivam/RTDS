#!/usr/bin/env python3
import requests
import re
from scapy.all import *

class PhishingDetector:
    def __init__(self, vt_api_key):
        self.api_key = vt_api_key
        self.vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
        self.suspicious_domains = set()
    
    def extract_urls(self, packet):
        urls = []
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # Extract URLs from HTTP traffic
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            urls = re.findall(url_pattern, payload)
        return urls
    
    def check_url_vt(self, url):
        params = {
            'apikey': self.api_key,
            'resource': url
        }
        try:
            response = requests.get(self.vt_url, params=params)
            result = response.json()
            
            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                if positives > 0:
                    return f"🎣 Phishing URL Detected: {url} ({positives}/{total} engines)"
        except:
            pass
        return None
    
    def analyze_packet(self, packet):
        urls = self.extract_urls(packet)
        for url in urls:
            if url not in self.suspicious_domains:
                alert = self.check_url_vt(url)
                if alert:
                    self.suspicious_domains.add(url)
                    return alert
        return None

def start_phishing_detection(api_key, interface=None):
    detector = PhishingDetector(api_key)
    
    def packet_handler(packet):
        alert = detector.analyze_packet(packet)
        if alert:
            print(alert)
    
    sniff(iface=interface, prn=packet_handler, filter="tcp port 80 or tcp port 443")

if __name__ == "__main__":
    API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your API key
    start_phishing_detection(API_KEY)
