#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firewall_exhaustion import _X

def demo():
    print("=" * 60)
    print("Spiritus - Network Resilience Demo")
    print("=" * 60)
    x = _X()
    methods = [
        ("m1", "Enhanced SYN"), ("m2", "UDP Flood"), ("m3", "ICMP Flood"),
        ("m4", "HTTP Connection"), ("m5", "DNS Amplification"), ("m6", "Randomized"),
        ("m7", "SSL/TLS Handshake"), ("m8", "QUIC Protocol"), ("m9", "HTTP/2"),
        ("m10", "Packet Fragmentation"), ("m11", "Adaptive Coordinated")
    ]
    for i, (m, d) in enumerate(methods, 1):
        print(f"  {i:2}. {m:4} - {d}")
    print("\nPatterns: rotating, aggressive, stealthy, maximal")
    print("Use: x.m1(target_ip, target_port, duration, rate)")
    print("Stop: x.stop()")

if __name__ == "__main__":
    demo()