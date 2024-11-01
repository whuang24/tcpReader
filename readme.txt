
<a id="readme-top"></a>

<br />
<div align="center">

  <h3 align="center">TCP Reader</h3>

  <p align="center">
    A python built PCAP file reader that reads TCP communications between a client and server.
  </p>
</div>


## About The Project

This is a python software that allows allows the user to understand each of the connections inside a PCAP file, some of their specific details, a generalized statistics report of all the connections, and lastly a generalized report of the complete connections' statistics.

The project primarily consists of two files, tcpReader.py and packet_struct.py.

In tcpReader.py, the file reads a pcap file from terminal input and identifies breaks it down starting from the global header and cycles through each of the packets.
For each packet, it first reads the packet header to determine that it is valid, then it determines the lenght of the packet based on the packet header.
From the packet length, it can then dissect the packet into Ethernet header (14 bytes), which is ignored, IP header, TCP header, and payload/tcp segment amount.
For IP Header and TCP Header, the code goes through their bytes to obtain whatever data is required for output, then stores the packet into a packet object and put into a connection object.
After going through the entire PCAP file, all of the packets and their data are properly organized and sorted into the different connection objects in a list.
Lastly, the connection objects are looped through to output their collected info.

In packet_struct.py, the file contains the class objects for IP Header, TCP Header, Packet Data, and Connections.
- IP Header contains {source ip, dest ip, the header length, and the total length of the ip data}
- TCP Header contains {source port, dest port, tcp seq number, tcp ack number, the length of the tcp header, window size of the tcp connection, checksum, and ugp}
- Packet Data contains {an ip header, a TCP header, the timestamp of the packet, a RTT value, a RTT flag, buffer, and tcp_segment = length of tcp payload (Modified)}
- Connection contains {all of the data required to be outputted in the report}

The following are Connection Class methods
- init = initialize a connection object, sets the unique identifier data based on packet, and also sets start and end time while setting everything else to 0, empty, or False
- record_packet = increments counters and data amount based on packet source and destination. Then adds RTT to the connection using method 2 to match recorded packet's ACK number with previous packets' seq number + tcp_segment length. 
If it matches, then use these two packet pairs to calculate the RTT. Lastly, adds the packet to the list of packets for the connection and the window size of the packet's tcp header to the connection's list of window sizes.
- generate_report = organizes all of the collected data and prints them out in the desired format.


## Project Limitations

The following is a list of the limitations that the project currently contain

* It can only access read TCP packets, not UDP or other formats.
* The RTT time may be overestimated due to using RTT calculation method 1.
* It is not capable of detecting lost packets or broken packets due to congestion.


## Getting Started

Type inside the terminal
```
python tcpReader.py <pcap file address>
```

Example
```
python tcpReader.py sample-capture-file.cap 
```
