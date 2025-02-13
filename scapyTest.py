from scapy.all import *

# Create a UDP packet with 4 NOPs (0x01)
#packet = IP(dst="192.168.1.1", ttl=1, options=b"\x01\x01\x01\x01") / UDP(dport=44444, sport=56113) / Raw(load="Hello!")

# Send and capture response
#response = sr1(packet, timeout=2)
#if response:
#    response.show()
#else:
#    print("No response received")