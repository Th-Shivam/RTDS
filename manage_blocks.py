#!/usr/bin/env python3

import argparse
import sys
import os
import time
from datetime import datetime

from ip_blocker import IPBlocker


def is_root():
    """Check root safely (Linux only)"""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


def main():
    parser = argparse.ArgumentParser(
        description="RTDS IP Blocker Management Tool"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Available commands"
    )

    # ---------------- Block ----------------
    block_parser = subparsers.add_parser("block", help="Block an IP address")
    block_parser.add_argument("ip", help="IP address to block")
    block_parser.add_argument(
        "--reason",
        default="Manual block",
        help="Reason for blocking"
    )
    block_parser.add_argument(
        "--duration",
        type=int,
        default=3600,
        help="Block duration in seconds (0 = permanent)"
    )

    # ---------------- Unblock ----------------
    unblock_parser = subparsers.add_parser("unblock", help="Unblock an IP address")
    unblock_parser.add_argument("ip", help="IP address to unblock")

    # ---------------- List ----------------
    subparsers.add_parser("list", help="List all blocked IPs")

    # ---------------- Stats ----------------
    subparsers.add_parser("stats", help="Show blocking statistics")

    # ---------------- Emergency ----------------
    subparsers.add_parser("emergency", help="Emergency unblock ALL IPs")

    # ---------------- Whitelist ----------------
    whitelist_parser = subparsers.add_parser(
        "whitelist", help="Add IP or CIDR range to whitelist"
    )
    whitelist_parser.add_argument("ip_or_range", help="IP or CIDR (e.g. 192.168.1.0/24)")

    args = parser.parse_args()

    # Root warning (non-fatal)
    if not is_root():
        print("⚠️  Warning: Not running as root.")
        print("   Some iptables operations may fail.")
        print("   Recommended: sudo python3 manageblock.py\n")

    # Logger callback
    def log_callback(message, attack_type="INFO"):
        print(f"[{attack_type}] {message}")

    blocker = IPBlocker(log_callback=log_callback)

    try:
        # ---------------- BLOCK ----------------
        if args.command == "block":
            ok = blocker.block_ip(
                ip=args.ip,
                reason=args.reason,
                duration=args.duration
            )
            if not ok:
                raise RuntimeError("Block operation failed")

            dur = "permanent" if args.duration == 0 else f"{args.duration}s"
            print(f"✅ IP {args.ip} blocked ({dur})")

        # ---------------- UNBLOCK ----------------
        elif args.command == "unblock":
            ok = blocker.unblock_ip(args.ip)
            if not ok:
                raise RuntimeError("Unblock operation failed")

            print(f"✅ IP {args.ip} unblocked")

        # ---------------- LIST ----------------
        elif args.command == "list":
            blocked = blocker.get_blocked_ips()

            if not blocked:
                print("📋 No IPs are currently blocked")
                return

            print(f"📋 Blocked IPs ({len(blocked)})")
            print("-" * 90)
            print(f"{'IP':<18} {'Reason':<25} {'Blocked At':<22} {'Status'}")
            print("-" * 90)

            for ip, info in blocked.items():
                blocked_at = datetime.fromtimestamp(
                    info["timestamp"]
                ).strftime("%Y-%m-%d %H:%M:%S")

                expires = info.get("expires", 0)
                if expires > 0:
                    remaining = int(max(0, expires - time.time()))
                    status = f"Expires in {remaining}s"
                else:
                    status = "Permanent"

                print(f"{ip:<18} {info['reason']:<25} {blocked_at:<22} {status}")

        # ---------------- STATS ----------------
        elif args.command == "stats":
            stats = blocker.get_block_stats()

            print("📊 RTDS Block Statistics")
            print("-" * 40)
            print(f"Active blocks      : {stats['active_blocks']}")
            print(f"Temporary blocks   : {stats['temporary_blocks']}")
            print(f"Permanent blocks   : {stats['permanent_blocks']}")
            print(f"Whitelist entries  : {stats['whitelist_entries']}")

            if stats.get("block_reasons"):
                print("\nBlock reasons:")
                for r, c in stats["block_reasons"].items():
                    print(f"  • {r}: {c}")

        # ---------------- EMERGENCY ----------------
        elif args.command == "emergency":
            confirm = input(
                "⚠️  This will UNBLOCK ALL IPs. Type 'YES' to confirm: "
            )
            if confirm == "YES":
                blocker.emergency_unblock_all()
                print("🚨 All IPs have been unblocked")
            else:
                print("❌ Emergency unblock cancelled")

        # ---------------- WHITELIST ----------------
        elif args.command == "whitelist":
            ok = blocker.add_to_whitelist(args.ip_or_range)
            if not ok:
                raise RuntimeError("Failed to add to whitelist")

            print(f"✅ {args.ip_or_range} added to whitelist")

    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
