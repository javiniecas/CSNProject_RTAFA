import pyshark
import re
import requests
from collections import defaultdict

interface = "Wi-Fi" # replace with your desired interface

API_KEY = '0973fa42c6eb05d2d3cbb9b1fb3e6282f899bd6210ba14d691906e5e2142989e09a69f03b39a9e45'
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

pcap_reader = pyshark.LiveCapture(
    interface=interface,
)

connection_counts = defaultdict(int)

flows = defaultdict(lambda: {"count": 0, "timestamps": []})

def check_ip_abuse(ip):
    """
    Check if the given IP is flagged as malicious on AbuseIPDB.
    Returns True if the IP is malicious, False otherwise.
    """
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        abuse_score = data['data']['abuseConfidenceScore']
        if abuse_score > 50:  # Customize the threshold as needed
            print(f"Detected malicious IP: {ip} (Abuse Score: {abuse_score})")
            return True
    except requests.RequestException as e:
        print(f"Error querying AbuseIPDB for IP {ip}: {e}")
    return False

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
    if length_str and (int(length_str) > 1500):
        print("Anomaly Detected: Large packet size (length > 1500 bytes).")
    if int(length_str) < 50:
        print("Anomaly Detected: Small packet size (length < 50 bytes).")
        return True

    # 2. Check for suspicious IPs
    if 'ip' in packet:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        # Query the source IP
        if check_ip_abuse(src_ip):
            print(f"Anomaly Detected: Malicious source IP: {src_ip}.")
            return True

        # Query the destination IP
        if check_ip_abuse(dst_ip):
            print(f"Anomaly Detected: Malicious destination IP: {dst_ip}.")
            return True

        # 3. Check for suspicious port activity
        if 'tcp' in packet:
            dst_port = packet.tcp.dstport
            connection_counts[(src_ip, dst_port)] += 1

            # If a source IP is connecting to >50 unique destination ports
            unique_ports = len(set(dst_port for src_ip_key, dst_port in connection_counts.keys() if src_ip_key == src_ip))
            if unique_ports > 50:
                print(f"Anomaly Detected: Potential port scan from {src_ip} (connected to {unique_ports} ports).")
                return True

    # 4. Check for suspicious DNS queries
    if 'dns' in packet:
        try:
            qry_name = packet.dns.qry_name.lower()
            domain_parts = qry_name.split('.')
            for part in domain_parts:
                cleaned = re.sub('[^a-z]', '', part)
                vowel_count = sum(cleaned.count(v) for v in 'aeiou')
                # Suspicious domain with long name and few vowels
                if len(cleaned) >= 10 and vowel_count <= 2:
                    print(f"Anomaly Detected: Suspicious domain name queried: {qry_name}.")
                    return True
            # Suspicious domain patterns
            if qry_name.endswith('.xyz') or len(qry_name) > 20:
                print(f"Anomaly Detected: Unusual domain name queried: {qry_name}.")
                return True
                
        except AttributeError:
            pass

    # If no anomaly is detected
    return False

try:
    for packet in pcap_reader.sniff_continuously(packet_count=100):
        print(f'Packet Number: {packet.number}')
        print(f'Timestamp: {packet.sniff_time}')

        # 1. Track the packet (for flow statistics)
        track_packet(packet)

        # 2. Check for anomalies
        if is_anomalous(packet):
            print("\n Anomalous Packet Detected:")
            print(packet)  
            continue  

        # 3. Print packet details
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


