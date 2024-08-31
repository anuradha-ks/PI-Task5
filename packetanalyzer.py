from scapy.all import sniff, IP, TCP, UDP

def packet_sniffer(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet.payload

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        if TCP in packet:
            print("TCP Payload:")
            print(payload)
        elif UDP in packet:
            print("UDP Payload:")
            print(payload)
        else:
            print("Other Payload:")
            print(payload)
        
        print("-" * 50)

# Capture packets
sniff(prn=packet_sniffer, count=8)
