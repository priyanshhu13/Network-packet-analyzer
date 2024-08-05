import pandas as pd
from scapy.all import sniff, get_if_list, IP, TCP, UDP

def packet_callback(packet):
    packet_info = {
        "timestamp": packet.time,
        "src_ip": packet[IP].src if IP in packet else None,
        "dst_ip": packet[IP].dst if IP in packet else None,
        "src_port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None),
        "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None),
        "protocol": packet[IP].proto if IP in packet else None,
        "length": len(packet),
        "summary": packet.summary()
    }
    packets.append(packet_info)
    # Print packet information to the terminal
    print(packet_info)

def capture_packets(interface, packet_count):
    sniff(iface=interface, prn=packet_callback, count=packet_count, store=0)

def list_interfaces():
    interfaces = get_if_list()
    print("Available interfaces:")
    for iface in interfaces:
        print(iface)

def save_to_excel(filename):
    df = pd.DataFrame(packets)
    df.to_excel(filename, index=False)

def main():
    global packets
    packets = []

    list_interfaces()
    interface = input("Enter the interface name to sniff: ")
    packet_count = int(input("Enter the number of packets to capture: "))
    capture_packets(interface, packet_count)

    filename = input("Enter the filename to save the data (with .xlsx extension): ")
    save_to_excel(filename)
    print(f"Data saved to {filename}")

if __name__ == "__main__":
    main()