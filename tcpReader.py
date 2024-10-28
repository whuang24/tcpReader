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
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(ordering + 'IIII', packet_header)
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
                continue
        
            if rst_flag:
                status = f"S{syn_count}F{fin_count}/R"
            else:
                status = f"S{syn_count}F{fin_count}"

            connection_id = (source_ip, source_port, dest_ip, dest_port)
            if connection_id not in connections:
                connections[connection_id] = Connection(source_ip, source_port, dest_ip, dest_port, timestamp, rst_flag)

            connection = connections[connection_id]
            connection.record_packet(source_ip, dest_ip, data_length, timestamp)

            packet_no += 1

    return packets

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No file supplied, please add a .cap file as input.")
        sys.exit(1)
        
    capFile = sys.argv[1]
    packets = parse_pcap(capFile)

    total_string = f"A) Total number of connections: {len(connections)}"

    separator = "________________________________________________\n"

    connection_details_string = "B) Connection's details\n"

    general_string = f"C) General\n"

    print(total_string)
    print(separator)
    print(connection_details_string)

    for i, (conn_id, connection) in enumerate(connections.items(), 1):
        print(connection.generate_report(i))

    print(separator)
    print(general_string)
