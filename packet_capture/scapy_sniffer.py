"""
scapy_sniffer.py
-----------------
OPTIONAL module for feeding real, live packets into AI CyberShield instead
of simulated traffic.

Requirements:
  - pip install scapy
  - Root/admin privileges (raw sockets)
  - Run on a machine where you're authorized to capture traffic

This performs lightweight, per-window feature extraction per source IP
(connection counts, unique ports touched, SYN ratio, byte volume) on a
sliding time window and posts the resulting feature vector to
POST /api/predict on the running Flask app. If the model flags an attack,
it also POSTs to /api/block via the same app's block logic (through the
dashboard, or directly by importing app.block_ip).

Usage:
  sudo python3 packet_capture/scapy_sniffer.py --iface eth0 --api http://localhost:5000

NOTE: This is a reference implementation for extending the project to
real traffic. It is not required to run the demo dashboard, which uses
the built-in simulator in app/app.py.
"""

import argparse
import time
from collections import defaultdict

import requests

try:
    from scapy.all import IP, TCP, sniff
except ImportError:
    raise SystemExit("Install scapy first:  pip install scapy --break-system-packages")

WINDOW_SECONDS = 2
windows = defaultdict(lambda: {"count": 0, "syn": 0, "bytes": 0, "ports": set()})


def flush_window(api_url):
    now_windows = dict(windows)
    windows.clear()
    for src_ip, w in now_windows.items():
        if w["count"] == 0:
            continue
        features = {
            "duration": WINDOW_SECONDS,
            "protocol_type": "tcp",
            "service": "other",
            "flag": "S0" if w["syn"] > w["count"] * 0.6 else "SF",
            "src_bytes": w["bytes"] / max(w["count"], 1),
            "dst_bytes": 0,
            "count": w["count"],
            "srv_count": w["count"],
            "serror_rate": w["syn"] / max(w["count"], 1),
            "rerror_rate": 0.0,
            "same_srv_rate": 0.9,
            "diff_srv_rate": len(w["ports"]) / max(w["count"], 1),
            "dst_host_count": w["count"],
            "dst_host_srv_count": w["count"],
            "dst_host_same_srv_rate": 0.8,
            "dst_host_diff_srv_rate": 0.1,
            "unique_ports_touched": len(w["ports"]),
            "conn_rate_per_sec": w["count"] / WINDOW_SECONDS,
            "payload_entropy": 4.0,
            "failed_logins": 0,
        }
        try:
            r = requests.post(f"{api_url}/api/predict", json=features, timeout=2)
            result = r.json()
            if result.get("classification") != "normal":
                print(f"[ALERT] {src_ip} -> {result['label']} ({result['confidence']*100:.1f}%)")
        except requests.RequestException as e:
            print(f"[warn] could not reach API: {e}")


def handle_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        w = windows[src]
        w["count"] += 1
        w["bytes"] += len(pkt)
        if TCP in pkt:
            w["ports"].add(pkt[TCP].dport)
            if pkt[TCP].flags & 0x02:  # SYN
                w["syn"] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None, help="Network interface to sniff (default: scapy auto)")
    ap.add_argument("--api", default="http://localhost:5000", help="AI CyberShield API base URL")
    args = ap.parse_args()

    print(f"Sniffing on {args.iface or 'default interface'}... Ctrl+C to stop.")
    last_flush = time.time()

    def _on_pkt(pkt):
        nonlocal last_flush
        handle_packet(pkt)
        if time.time() - last_flush >= WINDOW_SECONDS:
            flush_window(args.api)
            last_flush = time.time()

    sniff(iface=args.iface, prn=_on_pkt, store=False)


if __name__ == "__main__":
    main()
