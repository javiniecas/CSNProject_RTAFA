import pyshark
import re

interface = "Wi-Fi" # replace with your desired interface

pcap_reader = pyshark.LiveCapture(
    interface=interface,
    bpf_filter="tcp port 80 or tcp port 443"
)
from collections import defaultdict
connection_counts = defaultdict(int)
flows = defaultdict(lambda: {"count": 0, "timestamps": []})

def track_packet(packet):
    if 'ip' in packet and ('tcp' in packet or 'udp' in packet):
        src = packet.ip.src
        dst = packet.ip.dst
        protocol = 'tcp' if 'tcp' in packet else 'udp'
        key = (src, dst, protocol)
        
        flows[key]["count"] += 1
        flows[key]["timestamps"].append(packet.sniff_timestamp)



def is_anomalous(packet):
    """
    Return True if the packet meets some 'suspicious' criteria,
    otherwise False.
    """

    # 1. Check packet size
    length_str = getattr(packet, 'length', None)
    if length_str and int(length_str) > 1500 or length_str and int(length_str) < 50:
        return True

    # 2. Check for suspicious IPs (example)
    if 'ip' in packet:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        
        # Suppose we have a known malicious IP:
        MALICIOUS_IPS = {'1.2.3.4', '8.8.8.8'}  # Add an example IP
        if src_ip in MALICIOUS_IPS or dst_ip in MALICIOUS_IPS:
            return True

    # 3. Check for suspicious domains in DNS traffic
    if 'dns' in packet:
        try:
            qry_name = packet.dns.qry_name.lower()
            # Simplistic check: domain with >10 chars and few vowels
            domain_parts = qry_name.split('.')
            for part in domain_parts:
                cleaned = re.sub('[^a-z]', '', part)
                vowel_count = sum(cleaned.count(v) for v in 'aeiou')
                if len(cleaned) >= 10 and vowel_count <= 2:
                    return True
                if qry_name.endswith('.com') or len(qry_name) > 20:
                    return True
        except AttributeError:
            pass
    # 4
    if 'ip' in packet and 'tcp' in packet:
        src_ip = packet.ip.src
        dst_port = packet.tcp.dstport
        connection_counts[(src_ip, dst_port)] += 1

    # Example: flag if more than 50 unique destination ports
    if len(set(dst_port for src_ip, dst_port in connection_counts.keys() if src_ip == packet.ip.src)) > 50:
        print(f"Possible Port Scan Detected from {src_ip}")
        return True
    return False

try:
    for packet in pcap_reader.sniff_continuously(packet_count=100):
        print(f'Packet Number: {packet.number}')
        print(f'Timestamp: {packet.sniff_time}')

        if is_anomalous(packet):
            print("\n[!] Anomalous Packet Detected:")
            print(packet)  # Or print a subset of fields
        else:
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
                print(f'TCP Window Size: {packet.tcp.window_size}')
                print(f'TCP Checksum: {packet.tcp.checksum}')

            if 'udp' in packet:
                print(f'UDP Source Port: {packet.udp.srcport}')
                print(f'UDP Destination Port: {packet.udp.dstport}')
                print(f'UDP Length: {packet.udp.length}')
                print(f'UDP Checksum: {packet.udp.checksum}')

            print("\n---------------------------------------------------------------------------------------------------\n")
except KeyboardInterrupt:
    print("\nCapture stopped.")

