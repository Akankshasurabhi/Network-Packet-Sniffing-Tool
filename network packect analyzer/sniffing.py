import scapy.all as scapy
def packet_call(packet):
    if packet.haslayer(scapy.IP):
        src_ip=packet[scapy.IP].src
        dst_ip=packet[scapy.IP].dst
        protocol =packet[scapy.IP].proto
        print(f"source ip:{src_ip} || destination ip: {dst_ip}|| protocol:{protocol}")
        if packet.haslayer(scapy.TCP):
            try:
                payload=packet[scapy.Raw].load
                decoded_payload=payload.decode('utf-8','ignore')
                print(f"TCP Payload:{decoded_payload[:50]}")
            except(IndexError,UnicodeDecodeError):
                print("unable to decode Tcp payload")
        elif packet.haslayer(scapy.UDP):
            try:
                payload=packet[scapy.Raw].load
                decoded_payload=payload.decode('utf-8','ignore')
                print(f"TCP Payload:{decoded_payload[:50]}")
            except(IndexError,UnicodeDecodeError):
                print("unable to decode Tcp payload")
def start_sniffing():
    scapy.sniff(store=False,prn=packet_call)
start_sniffing()