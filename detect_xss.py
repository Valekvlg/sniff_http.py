from scapy.all import sniff

def detect_xss(packet):
    if packet.haslayer("Raw"):
        data = packet["Raw"].load.decode(errors="ignore")
        if "<script>" in data or "alert(" in data:
            print("[XSS Detected] ->", data)

print("Starting XSS detection...")
sniff(filter="tcp port 80", prn=detect_xss, store=0)
