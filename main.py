import pyshark
import re

interface = "Wi-Fi" # replace with your desired interface

pcap_reader = pyshark.LiveCapture(interface=interface)
try:
    for packet in pcap_reader.sniff_continuously(packet_count=10):
        print(f'Packet Number: {packet.number}')
        print(f'Timestamp: {packet.sniff_time}')

        if 'eth' in packet:
            print(f'Source MAC: {packet.eth.src}')
            print(f'Destination MAC: {packet.eth.dst}')

        if 'ip' in packet:
            if 'IPV6 Layer' in str(packet.layers):
                protocol = re.search(r'(Next Header:)(.*)', str(packet.ipv6))
                protocol_type = protocol.group(2).strip().split(' ')[0]
                protocol_number = protocol.group(2).strip().split(' ')[1]
                print(f'IPv6, Protocol Type: {protocol_type} {protocol_number}')
            elif 'IP Layer' in str(packet.layers):
                protocol = re.search(r'(Protocol:)(.*)', str(packet.ip))
                protocol_type = protocol.group(2).strip().split(' ')[0]
                protocol_number = protocol.group(2).strip().split(' ')[1]
                print(f'IPv4, Protocol Type: {protocol_type} {protocol_number}')
            print(f'Source IP: {packet.ip.src}')
            print(f'Destination IP: {packet.ip.dst}')

        if 'tcp' in packet:
            print(f'TCP Source Port: {packet.tcp.srcport}')
            print(f'TCP Destination Port: {packet.tcp.dstport}')
            print(f'TCP {packet.tcp.flags.showname}')

        if 'udp' in packet:
            print(f'UDP Source Port: {packet.udp.srcport}')
            print(f'UDP Destination Port: {packet.udp.dstport}')

        if 'http' in packet:
            print(f'HTTP Method: {packet.http.request_method if hasattr(packet.http, 'request_method') else 'N/A'}')
            print(f'HTTP Host: {packet.http.host if hasattr(packet.http, 'host') else 'N/A'}')
            print(f'HTTP URI: {packet.http.request_uri if hasattr(packet.http, 'request_uri') else 'N/A'}')

        print("\n---------------------------------------------------------------------------------------------------\n")
except KeyboardInterrupt:
    print("\nCapture stopped.")