#!/usr/bin/env python3
import time
import math
from collections import defaultdict, deque
from scapy.all import IP, TCP, UDP, ICMP

class EnhancedDDoSDetector:
    def __init__(self):
        self.traffic_patterns = defaultdict(lambda: {
            'packets': deque(maxlen=60),
            'sizes': deque(maxlen=100),
            'ports': set(),
            'flags': defaultdict(int),
            'intervals': deque(maxlen=50)
        })
        self.baseline_traffic = defaultdict(float)
        self.anomaly_scores = defaultdict(float)
        
    def analyze_packet(self, packet):
        if not packet.haslayer(IP):
            return None
            
        src_ip = packet[IP].src
        current_time = time.time()
        pattern = self.traffic_patterns[src_ip]
        
        # Update traffic pattern
        pattern['packets'].append(current_time)
        pattern['sizes'].append(len(packet))
        
        if packet.haslayer(TCP):
            pattern['ports'].add(packet[TCP].dport)
            pattern['flags'][packet[TCP].flags] += 1
        elif packet.haslayer(UDP):
            pattern['ports'].add(packet[UDP].dport)
            
        # Calculate intervals
        if len(pattern['packets']) > 1:
            interval = current_time - pattern['packets'][-2]
            pattern['intervals'].append(interval)
        
        return self._detect_anomaly(src_ip, current_time)
    
    def _detect_anomaly(self, src_ip, current_time):
        pattern = self.traffic_patterns[src_ip]
        
        # Rate-based detection
        recent_packets = [t for t in pattern['packets'] if current_time - t <= 10]
        pps = len(recent_packets) / 10
        
        # Behavioral analysis
        size_variance = self._calculate_variance(list(pattern['sizes']))
        interval_variance = self._calculate_variance(list(pattern['intervals']))
        port_diversity = len(pattern['ports'])
        
        # Anomaly scoring
        score = 0
        alerts = []
        
        # High packet rate
        if pps > 50:
            score += min(pps / 10, 10)
            
        # Low size variance (identical packets)
        if size_variance < 10 and len(pattern['sizes']) > 20:
            score += 5
            alerts.append(f"Identical packet sizes detected")
            
        # Regular intervals (bot-like)
        if interval_variance < 0.01 and len(pattern['intervals']) > 10:
            score += 7
            alerts.append(f"Bot-like regular intervals")
            
        # Port scanning + high rate
        if port_diversity > 20 and pps > 10:
            score += 8
            alerts.append(f"Port scanning with high rate")
            
        # SYN flood detection
        syn_ratio = pattern['flags'].get(2, 0) / max(sum(pattern['flags'].values()), 1)
        if syn_ratio > 0.8 and pps > 20:
            score += 9
            alerts.append(f"SYN flood pattern")
        
        self.anomaly_scores[src_ip] = score
        
        if score > 15:
            return f"🚨 ADVANCED DDoS: {src_ip} (Score: {score:.1f}, Rate: {pps:.1f}pps) - {', '.join(alerts)}"
        elif score > 8:
            return f"⚠️ Suspicious traffic: {src_ip} (Score: {score:.1f}) - {', '.join(alerts)}"
            
        return None
    
    def _calculate_variance(self, values):
        if len(values) < 2:
            return 0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)
