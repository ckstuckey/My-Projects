#!/usr/bin/env python3
# Simple ARP network scanner using Scapy
# Run with root privileges (sudo) because sending/receiving raw packets requires elevated permissions.

from scapy.all import *  # Import all Scapy functions/classes (Ether, ARP, srp, etc.)

print("🔎 Network Scanner running...\n")

# Network interface to send packets from (change to your machine's active interface, e.g. "en0" on macOS)
interface = "en0"

# Target IP range in CIDR notation — this scanner will probe every host in this subnet
ip_range = "10.0.0.0/24"

# Ethernet broadcast MAC address (used to send the ARP request to all hosts on the LAN)
broadcastMac = "ff:ff:ff:ff:ff:ff"

# Build the packet:
#   Ether(dst=broadcastMac) -> Ethernet frame with destination set to broadcast
#   / ARP(pdst=ip_range)   -> ARP layer asking "who has <each IP in ip_range>?"
packet = Ether(dst=broadcastMac) / ARP(pdst=ip_range)

# srp() -> Send and receive packets at layer 2 (Ethernet). Returns (answered, unanswered).
#   timeout=2  -> wait up to 2 seconds for replies for each request
#   iface=interface -> send on the specified network interface
#   inter=0.1  -> wait 0.1 seconds between sending each packet (rate control)
ans, unans = srp(packet, timeout=2, iface=interface, inter=0.1)

# Iterate over answered packets. Each element in 'ans' is a tuple (sent_packet, received_packet)
for sent, received in ans:
    # received.sprintf(...) formats the output using Scapy's sprintf placeholders:
    #   %Ether.src%  -> MAC address of the responding host
    #   %ARP.psrc%   -> IP address of the responding host (the source IP in the ARP reply)
    print(received.sprintf(r"%Ether.src% - %ARP.psrc%"))
