from scapy.all import *

# Create a UDP packet with 4 NOPs (0x01)
packet = IP(dst="142.250.185.14", ttl=64, options=b"") / ICMP()

# Send and capture response
response = sr1(packet, timeout=2)
if response:
    response.show()
else:
    print("No response received")