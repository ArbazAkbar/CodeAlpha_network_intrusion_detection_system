import scapy.all as scapy

# Define the network interface to capture packets from
interface = "wlan0"

# Define the packet capture filter (e.g., TCP packets only)
filter = "tcp"

# Start capturing packets
packets = scapy.sniff(iface=interface, filter=filter, count=100)

# Print the captured packets
for packet in packets:
    print(packet.show())
