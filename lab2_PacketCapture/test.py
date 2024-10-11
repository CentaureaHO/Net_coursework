from scapy.all import *

src_mac = "11:45:14:19:19:81"
tar_mac = "00:00:5e:00:01:0b"
target_ip = "10.128.0.1"

eth = Ether(src=src_mac, dst=tar_mac)

ip = IP(dst=target_ip)

icmp = ICMP()

packet = eth / ip / icmp

sendp(packet, iface="wlp0s20f3")

print(f"Sent packet from {src_mac} to {target_ip}")