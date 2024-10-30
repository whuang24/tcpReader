import struct
import sys
from packet_struct import IP_Header, TCP_Header, Packet_Data, Connection

connections = {}

# Helper function to parse pcap file headers
def parse_pcap(file_path):
    with open(file_path, 'rb') as f:

        # Obtaining global header and identifying big/small endianese
        global_header = f.read(24)

        magic_number = global_header[:4]

        if magic_number == b'\xa1\xb2\xc3\xd4':
            ordering = ">"
        elif magic_number == b'\xd4\xc3\xb2\xa1':
            ordering = "<"
        else:
            raise ValueError("Unsupported pcap format")
        
        packet_no = 0
        start_time = 0
        
        # Extract packets
        while True:
            syn = False
            fin = False
            rst_flag = False
            
            # Reads the packet header, and ends checking if the packet_header does not exist
            packet_header = f.read(16)
            if not packet_header:
                break

            # Skips over incomplete packet header if it is incomplete
            if len(packet_header) < 16:
                continue
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(ordering + 'IIII', packet_header)

            # Reads the packet data
            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                continue

            if start_time == 0:
                start_time = ts_sec + ts_usec * 1e-6

            pkt = Packet_Data()
            pkt.buffer = packet_data
            pkt.packet_No_set(packet_no)
            pkt.timestamp_set(struct.pack('I', ts_sec), struct.pack('I', ts_usec), start_time)

            # Reads the IP header
            ip_header = IP_Header()
            ip_header.get_IP(packet_data[26:30], packet_data[30:34])
            ip_header.get_header_len(packet_data[14:15])

            # Reads the TCP header
            tcp_header = TCP_Header()
            tcp_header.get_src_port(packet_data[34:36])
            tcp_header.get_dst_port(packet_data[36:38])
            tcp_header.get_data_offset(packet_data[46:47])
            tcp_header.get_flags(packet_data[47:48])

            pkt.IP_header = ip_header
            pkt.TCP_header = tcp_header

            source_ip = ip_header.src_ip
            dest_ip = ip_header.dst_ip

            source_port = tcp_header.src_port
            dest_port = tcp_header.dst_port

            data_offset = tcp_header.data_offset
            flags = tcp_header.flags
            data_length = incl_len - (14 + ip_header.ip_header_len + data_offset)

            if flags["SYN"]:
                syn = True

            if flags["FIN"]: 
                fin = True
            
            if flags["RST"]:
                rst_flag = True


            if (source_ip, source_port) < (dest_ip, dest_port):
                connection_id = ((source_ip, source_port), (dest_ip, dest_port))
            else:
                connection_id = ((dest_ip, dest_port), (source_ip, source_port))

            if connection_id not in connections:
                connections[connection_id] = Connection(source_ip, source_port, dest_ip, dest_port, pkt.timestamp)

            connection = connections[connection_id]
            connection.record_packet(source_ip, dest_ip, data_length, pkt.timestamp, syn, fin, rst_flag)

            packet_no += 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No file supplied, please add a .cap file as input.")
        sys.exit(1)
        
    capFile = sys.argv[1]
    packets = parse_pcap(capFile)

    complete_connections = 0
    reset_connections = 0
    unclosed_connections = 0

    separator = "________________________________________________\n"

    print(f"A) Total number of connections: {len(connections)}")
    print(separator)
    print("B) Connection's details\n")

    for i, (conn_id, connection) in enumerate(connections.items(), 1):
        if connection.rst_flag:
            reset_connections += 1
        
        if connection.fin_count == 0:
            unclosed_connections += 1
        else:
            complete_connections += 1

        print(connection.generate_report(i))

    print(separator)
    print(f"C) General\n")
    print(f"Total number of complete TCP connections: {complete_connections}")
    print(f"Number of reset TCP connections: {reset_connections}")
    print(f"Number of TCP connections that were still open when the trace capture ended: {unclosed_connections}")
