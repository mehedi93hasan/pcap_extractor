# pcap_extractor.py
import sys
from collections import Counter
try:
    from scapy.all import rdpcap, IP
except ImportError:
    print("Error: Scapy not installed. Please install it first.")
    input("Press Enter to exit...")
    sys.exit()

def extract_features(pcap_file):
    print(f"Analyzing {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"File {pcap_file} not found.")
        return

    src_ips = []
    dst_ips = []
    packet_sizes = []

    for packet in packets:
        if IP in packet:
            src_ips.append(packet[IP].src)
            dst_ips.append(packet[IP].dst)
            packet_sizes.append(len(packet))

    print("\n--- REPORT ---")
    print(f"Total Packets: {len(packets)}")
    print(f"Top 5 Source IPs: {Counter(src_ips).most_common(5)}")
    print(f"Top 5 Dest IPs: {Counter(dst_ips).most_common(5)}")
    print(f"Average Packet Size: {sum(packet_sizes)/len(packet_sizes):.2f} bytes")
    print("----------------")

if __name__ == "__main__":
    print("PCAP Feature Extractor")
    target_file = input("Enter the path to your .pcap file: ")
    # Remove quotes if user dragged and dropped file
    target_file = target_file.strip('"')
    extract_features(target_file)
    input("\nPress Enter to close...")
