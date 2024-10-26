import struct
import sys
from packet_struct import IP_Header, TCP_Header, packet

# Helper function to parse pcap file headers
def parse_pcap(file_path):
    with open(file_path, 'rb') as f:
        pcap_header = f.read(24)  # Read the global header (24 bytes for pcap format)
        
        # Extract packets
        packet_no = 1
        packets = []
        while True:
            packet_header = f.read(16)  # Each packet header is 16 bytes
            if len(packet_header) < 16:
                break  # End of file
            
            # Parse packet header to get timestamp and packet length
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)
            
            # Read the actual packet data
            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                break
            
            # Create and populate a packet object
            pkt = struct.packet()
            pkt.packet_No_set(packet_no)
            pkt.timestamp_set(struct.pack('I', ts_sec), struct.pack('I', ts_usec), 0)  # orig_time=0 for the first packet

            # Extract IP and TCP header information
            parse_ip_header(pkt, packet_data)
            parse_tcp_header(pkt, packet_data)
            
            packets.append(pkt)
            packet_no += 1

    return packets

# Extract IP header details
def parse_ip_header(pkt, packet_data):
    # Ethernet header is 14 bytes; skip it to get to IP header
    ip_header_start = 14
    ip_header = packet_data[ip_header_start:ip_header_start+20]  # IP header is 20 bytes (without options)

    pkt.IP_header.get_IP(ip_header[12:16], ip_header[16:20])  # Source and destination IPs
    pkt.IP_header.get_header_len(ip_header[0:1])              # IP header length
    pkt.IP_header.get_total_len(ip_header[2:4])               # Total length

# Extract TCP header details
def parse_tcp_header(pkt, packet_data):
    # Locate TCP header after the IP header
    tcp_header_start = 14 + pkt.IP_header.ip_header_len
    tcp_header = packet_data[tcp_header_start:tcp_header_start+20]  # Minimum TCP header size is 20 bytes

    pkt.TCP_header.get_src_port(tcp_header[0:2])               # Source port
    pkt.TCP_header.get_dst_port(tcp_header[2:4])               # Destination port
    pkt.TCP_header.get_seq_num(tcp_header[4:8])                # Sequence number
    pkt.TCP_header.get_ack_num(tcp_header[8:12])               # Acknowledgment number
    pkt.TCP_header.get_data_offset(tcp_header[12:13])          # Data offset
    pkt.TCP_header.get_flags(tcp_header[13:14])                # TCP flags
    pkt.TCP_header.get_window_size(tcp_header[14:15], tcp_header[15:16])  # Window size

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No file supplied, please add a .cap file as input.")
        sys.exit(1)
        
    file_path = sys.argv[1]
    packets = parse_pcap(file_path)

    for pkt in packets:
        print(f"Packet #{pkt.packet_No}")
        print(f"Timestamp: {pkt.timestamp}")
        print(f"Source IP: {pkt.IP_header.src_ip}, Destination IP: {pkt.IP_header.dst_ip}")
        print(f"Source Port: {pkt.TCP_header.src_port}, Destination Port: {pkt.TCP_header.dst_port}")
        print(f"Flags: {pkt.TCP_header.flags}")
        print("-" * 40)