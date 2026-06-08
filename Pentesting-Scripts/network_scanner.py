from scapy.all import ARP, Ether, srp
import argparse

parser = argparse.ArgumentParser(description="Simple Network Scanner")

# Specify a network range in CIDR notation.
# Examples:
#   192.168.1.0/24
#   10.0.0.0/24
#
# Do NOT use:
#   10.0.0.X
#   192.168.1.X
#
# A /24 network scans addresses .1 through .254 on that subnet.
parser.add_argument("target", help="Target network range (e.g. 192.168.1.0/24)")

args = parser.parse_args()

def scan_network(ip_range):

    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []

    # Extract the IP and MAC address from each response.
    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices

# The target must be a network range
# Examples:
# sudo python3 network_scanner.py 10.0.0.0/24
# sudo python3 network_scanner.py 172.16.1.0/24
print(f"\nScanning network: {args.target}\n")

clients = scan_network(args.target)

print("Available Devices:")
print("IP Address\t\tMAC Address")
print("-----------------------------------------")

for client in clients:
    print(f"{client['ip']}\t\t{client['mac']}")