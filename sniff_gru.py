from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer("Raw"):
        try:
            data = packet["Raw"].load.decode(errors="ignore")
            if "GET" in data or "POST" in data:
                print("[Captured Packet] ->", data)
        except Exception as e:
            print(f"Error decoding packet: {e}")

print("Starting packet sniffing on port 80...")
sniff(filter="tcp port 80", prn=packet_callback, store=0)