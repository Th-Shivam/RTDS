import time
import os
import argparse
import threading
from collections import OrderedDict, defaultdict
from scapy.all import sniff, get_if_addr, get_if_list
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP

# --- Configuration Constants ---
MAX_ARP_ENTRIES = 1000  # Maximum number of entries to store in the ARP cache.

class RTDSMonitor:
    """
    A class to encapsulate all state and logic for the Real-time Detection System.
    """
    def __init__(self, iface: str, ddos_threshold: int, syn_threshold: int, log_file: str):
        """
        Initializes the monitor with user-defined settings.

        Args:
            iface: The network interface to sniff on.
            ddos_threshold: The packets-per-second threshold for volumetric DDoS detection.
            syn_threshold: The packets-per-second threshold for SYN flood detection.
            log_file: The file path to save alert logs.
        """
        self.iface = iface
        self.ddos_threshold = ddos_threshold
        self.syn_threshold = syn_threshold
        self.log_file = log_file

        # --- State Variables ---
        self.packet_counts: dict[str, int] = defaultdict(int)
        self.syn_counts: dict[str, int] = defaultdict(int)
        self.arp_table: OrderedDict[str, str] = OrderedDict()
        
        self.total_packets: int = 0
        self.total_attacks: int = 0
        self.start_time: float = time.time()
        self.last_reset: float = time.time()
        
        # --- Local Network Info ---
        try:
            self.local_ip: str = get_if_addr(self.iface)
        except Exception:
            self.local_ip: str = "Unknown"
            print(f"[!] Warning: Could not get local IP for interface '{self.iface}'. Check interface name or permissions.")

    def log_alert(self, message: str, attack_type: str = "UNKNOWN"):
        """
        Appends a timestamped alert message to the log file.

        Args:
            message: The alert message string.
            attack_type: A label for the type of attack detected.
        """
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_file, "a", encoding='utf-8') as f:
                f.write(f"[{timestamp}] [{attack_type}] {message}\n")
        except Exception as e:
            print(f"[!] Log file error: {e}")

    def detect_ddos_attack(self, packet):
        """
        Analyzes a packet for signs of DDoS or SYN flood attacks.
        """
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        
        # Ignore packets from the local machine to avoid false positives.
        if src_ip == self.local_ip:
            return

        # Increment counts for the source IP.
        self.packet_counts[src_ip] += 1
        self.total_packets += 1

        # Check for SYN flag for SYN flood detection.
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # 0x02 is the SYN flag
            self.syn_counts[src_ip] += 1

    def check_thresholds(self):
        """
        Checks the packet rates against the defined thresholds every second.
        This function is called by the `analyze_packet` method.
        """
        current_time = time.time()
        if current_time - self.last_reset >= 1.0:
            # Volumetric DDoS Check
            for ip, count in self.packet_counts.items():
                if count > self.ddos_threshold:
                    self.total_attacks += 1
                    alert_msg = f"🚨 DDoS Attack from {ip} - Rate: {count} packets/sec"
                    print(f"\033[91m{alert_msg}\033[0m")
                    self.log_alert(alert_msg, "DDOS")

            # SYN Flood Check
            for ip, count in self.syn_counts.items():
                if count > self.syn_threshold:
                    self.total_attacks += 1
                    alert_msg = f"🚨 SYN Flood from {ip} - Rate: {count} SYN packets/sec"
                    print(f"\033[91m{alert_msg}\033[0m")
                    self.log_alert(alert_msg, "SYN_FLOOD")

            # Reset counts for the next second.
            self.packet_counts.clear()
            self.syn_counts.clear()
            self.last_reset = current_time

    def detect_mitm_attack(self, packet):
        """
        Analyzes a packet for signs of an ARP spoofing (MITM) attack.
        """
        if not packet.haslayer(ARP):
            return

        arp_op = packet[ARP].op
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        # Skip invalid or link-local addresses.
        if not src_ip or src_ip == "0.0.0.0" or src_ip.startswith("169.254"):
            return

        # Manage ARP table size
        if len(self.arp_table) >= MAX_ARP_ENTRIES:
            self.arp_table.popitem(last=False)

        # Detect ARP Spoofing via conflicting MAC addresses
        if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
            self.total_attacks += 1
            alert_msg = (
                f"⚠ MITM/ARP Spoofing Detected! "
                f"IP: {src_ip} | Old MAC: {self.arp_table[src_ip]} → New MAC: {src_mac}"
            )
            print(f"\033[93m{alert_msg}\033[0m")
            self.log_alert(alert_msg, "MITM")
        
        # Update the ARP table
        self.arp_table[src_ip] = src_mac
        print(f"\033[92m✓ New device mapped: {src_ip} → {src_mac}\033[0m")

    def analyze_packet(self, packet):
        """
        The main handler for each sniffed packet.
        """
        try:
            self.detect_ddos_attack(packet)
            self.check_thresholds()
            self.detect_mitm_attack(packet)
        except Exception as e:
            # Catching a general exception for unexpected errors during analysis.
            print(f"[!] Analysis error: {e}")

    def show_statistics(self):
        """
        Displays real-time statistics of the monitoring process.
        """
        uptime = int(time.time() - self.start_time)
        hours, minutes, seconds = uptime // 3600, (uptime % 3600) // 60, uptime % 60
        
        print(
            f"\033[92m📊 Runtime: {hours:02d}:{minutes:02d}:{seconds:02d} | "
            f"Packets: {self.total_packets} | "
            f"Attacks: {self.total_attacks} | "
            f"ARP Entries: {len(self.arp_table)}\033[0m"
        )
        
        # Use a new timer to call this function again after 10 seconds.
        threading.Timer(10.0, self.show_statistics).start()

    def start_monitoring(self):
        """
        Starts the packet sniffing and monitoring process.
        """
        print("\033[2J\033[H")
        print("""
🔐 Enhanced RTDS v2.0 - Windows Ready
🛡 Detection: DDoS (volumetric + SYN) & MITM/ARP Spoofing
--------------------------------------------------
""")
        print(f"[*] Interface: {self.iface} | Local IP: {self.local_ip}")
        print(f"[*] DDoS Threshold: {self.ddos_threshold} pps | SYN Threshold: {self.syn_threshold} pps")
        print(f"[*] Log File: {self.log_file}\n")
        print("[*] Starting monitoring... (Press Ctrl+C to stop)\n")

        # Start the statistics timer.
        threading.Timer(10.0, self.show_statistics).start()
        
        # Start sniffing packets.
        try:
            # We filter for 'arp' or 'ip' packets to reduce overhead.
            sniff(filter="arp or ip", prn=self.analyze_packet, store=False, iface=self.iface)
        except PermissionError:
            print("\n[!] Permission denied! Run as Administrator/Root to capture packets.")
        except KeyboardInterrupt:
            print("\n🛑 MONITORING STOPPED")
        except Exception as e:
            print(f"\n[!] An error occurred during sniffing: {e}")
        finally:
            self.shutdown()

    def shutdown(self):
        """
        Prints final statistics and saves the log file on shutdown.
        """
        uptime = int(time.time() - self.start_time)
        print(f"\n📈 Total Runtime: {uptime//3600:02d}:{(uptime%3600)//60:02d}:{uptime%60:02d}")
        print(f"📦 Total Packets Analyzed: {self.total_packets}")
        print(f"🚨 Total Attacks Detected: {self.total_attacks}")
        print(f"🗂 ARP Table Entries: {len(self.arp_table)}")
        print(f"📄 Logs saved in: {self.log_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced RTDS - DDoS & MITM Detection")
    parser.add_argument("--ddos-threshold", type=int, default=100, help="DDoS packet threshold (pps)")
    parser.add_argument("--syn-threshold", type=int, default=50, help="SYN flood threshold (pps)")
    parser.add_argument("--log", type=str, default="rtds_alerts.log", help="Log file path")
    parser.add_argument("--iface", default="Wi-Fi", help="Network interface (Windows example: Wi-Fi)")
    args = parser.parse_args()
    
    # Check if the interface exists
    if args.iface not in get_if_list():
        print(f"[!] Error: The specified interface '{args.iface}' was not found.")
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        exit(1)
    
    monitor = RTDSMonitor(args.iface, args.ddos_threshold, args.syn_threshold, args.log)
    monitor.start_monitoring()
