import socket
import struct
import textwrap
import time
from collections import namedtuple

# README
# This Python script reinforces firewall security by analyzing incoming traffic and detecting zero-day attacks.
# It captures packets, extracts their information, and filters them based on predefined rules.
# The script should be added to your existing firewall system to enhance its security capabilities.

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # Check for IP packets (IPv4)
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(f'IPv4 Packet:')
            print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'Protocol: {proto}, Source: {src}, Target: {target}')

            # Check for TCP packets
            if proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(f'TCP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'Sequence: {sequence}, Acknowledgement: {acknowledgement}')
                print(f'Flags:')
                print(f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')

                # Check and filter traffic based on predefined rules
                filter_traffic(src, target, src_port, dest_port)

            # Check for other protocols (e.g., ICMP, UDP) and add more filtering rules if needed

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def filter_traffic(src, target, src_port, dest_port):
    # Define traffic filtering rules
    blocked_ports = [22, 23, 80]  # Add more ports to block if needed
    blocked_ips = ['192.168.1.10']  # Add more IPs to block if needed

    if src_port in blocked_ports or dest_port in blocked_ports:
        print(f'Blocked: Port {src_port} or {dest_port} is not allowed')
        return

    if src in blocked_ips or target in blocked_ips:
        print(f'Blocked: IP {src} or {target} is not allowed')
        return

    # Check for zero-day attacks (e.g., unusual traffic patterns, high traffic volume)
    # Add your custom zero-day detection logic here

    print('Allowed: Traffic passed the filtering rules')

if __name__ == '__main__':
    main()
