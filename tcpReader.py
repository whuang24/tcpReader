import struct
import sys
from packet_struct import IP_Header, TCP_Header, Packet_Data, Connection

connections = {}

# Helper function to parse pcap file headers
def parse_pcap(file_path):
    with open(file_path, 'rb') as f:
        global_header = f.read(24)

        magic_number = global_header[:4]

        if magic_number == b'\xa1\xb2\xc3\xd4':
            ordering = ">"
        elif magic_number == b'\xd4\xc3\xb2\xa1':
            ordering = "<"
        else:
            raise ValueError("Unsupported pcap format")
        
        # Extract packets
        packets = []
        packet_no = 1

        while True:
            header = f.read(16)
            if len(header) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(ordering + 'IIII', header)
            timestamp = ts_sec + ts_usec * 1e-6

            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                break

            ip_header = IP_Header()
            ip_header.get_IP(packet_data[26:30], packet_data[30:34])
            ip_header.get_header_len(packet_data[14:15])

            source_ip = ip_header.src_ip
            dest_ip = ip_header.dst_ip

            tcp_header = TCP_Header()
            tcp_header.get_src_port(packet_data[34:36])
            tcp_header.get_dst_port(packet_data[36:38])
            tcp_header.get_data_offset(packet_data[46:47])
            tcp_header.get_flags(packet_data[47:48])

            source_port = tcp_header.src_port
            dest_port = tcp_header.dst_port
            data_offset = tcp_header.data_offset
            flags = tcp_header.flags
            data_length = incl_len - (14 + ip_header.ip_header_len + data_offset)

            if flags & 0x02:
                syn_count += 1

            if flags & 0x01: 
                fin_count += 1
            
            if flags & 0x04:
                rst_flag = True
                break
            
            packets.append(pkt)
            packet_no += 1
        
        status = f"S{syn_count}F{fin_count}/R" if rst_flag else f"S{syn_count}F{fin_count}"

        connection_id = (source_ip, source_port, dest_ip, dest_port)
        if connection_id not in connections:
            connections[connection_id] = Connection(source_ip, source_port, dest_ip, dest_port, timestamp, status)

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
        
    capFile = sys.argv[1]
    packets = parse_pcap(capFile)

    for pkt in packets:
        print(f"Packet #{pkt.packet_No}")
        print(f"Timestamp: {pkt.timestamp}")
        print(f"Source IP: {pkt.IP_header.src_ip}, Destination IP: {pkt.IP_header.dst_ip}")
        print(f"Source Port: {pkt.TCP_header.src_port}, Destination Port: {pkt.TCP_header.dst_port}")
        print(f"Flags: {pkt.TCP_header.flags}")
        print("-" * 40)