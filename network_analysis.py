import os
import sys
# Importing key Scapy components
from scapy.all import rdpcap, IP, TCP, UDP, DNS 

def analyze_pcap_file(pcap_path):
    """
    Loads a PCAP file and performs basic network analysis using Scapy.
    This fulfills the P2/P3 Network Protocol Analysis and Packet Decoding features.
    """
    print(f"\n[+] Starting Network Analysis on PCAP file: {pcap_path}")
    
    if not os.path.exists(pcap_path):
        print(f"ERROR: PCAP file not found at {pcap_path}")
        return "Network analysis failed: PCAP file not found."

    try:
        # Load all packets from the PCAP file
        packets = rdpcap(pcap_path)
        total_packets = len(packets)
        
        print(f"Total packets loaded: {total_packets}")
        print("--- SUMMARY OF TOP 10 PACKETS (Packet Decoding) ---")
        
        protocol_counts = {}
        conversations = set()

        for i, packet in enumerate(packets):
            # Check for the IP layer (all packets with IP information)
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Identify the transport layer protocol
                if TCP in packet:
                    proto = 'TCP'
                elif UDP in packet:
                    proto = 'UDP'
                else:
                    proto = 'Other IP'
                
                # Track protocol frequency (P2 Network Protocol Analysis)
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

                # Track unique conversations (Source IP <-> Destination IP)
                conv_key = tuple(sorted((src_ip, dst_ip)))
                conversations.add(conv_key)

                # Print decoding summary for first 10 packets
                if i < 10:
                    summary = f"[{i+1}] {proto:<3} SRC: {src_ip:<15} DST: {dst_ip:<15}"
                    if TCP in packet:
                         summary += f" | Port: {packet[TCP].dport}"
                    elif DNS in packet:
                         summary += f" | DNS Query"
                         
                    print(summary)
        
        # --- Network Conversation Reconstruction Summary (P3) ---
        print("\n--- NETWORK CONVERSATION SUMMARY ---")
        print(f"Total Unique IP Conversations Found: {len(conversations)}")

        # --- Protocol Statistics ---
        print("\n--- PROTOCOL FREQUENCY ---")
        protocol_output = []
        for proto, count in sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True):
            protocol_output.append(f"{proto:<8}: {count} packets")
            print(protocol_output[-1])
        
        return f"Network Analysis complete. Total packets: {total_packets}. Total conversations: {len(conversations)}."

    except Exception as e:
        print(f"An error occurred during Scapy analysis: {e}")
        return f"Network Analysis failed: {e}"

# --- Example Execution ---
if __name__ == '__main__':
    MOCK_PCAP_FILE = "network_traffic.pcap" 
    
    if not os.path.exists(MOCK_PCAP_FILE):
        print(f"\n[!] Place a real network capture file here, naming it: {MOCK_PCAP_FILE}")
        with open(MOCK_PCAP_FILE, 'w') as f:
            f.write("")
        print("Cannot run analysis without a PCAP file.")
    else:
        analyze_pcap_file(MOCK_PCAP_FILE)