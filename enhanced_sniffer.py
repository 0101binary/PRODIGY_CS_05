#!/usr/bin/env python3
"""
Enhanced Packet Sniffer Tool - Educational Version
==================================================

Advanced packet sniffer with filtering, logging, and enhanced analysis capabilities.
This tool is designed for educational purposes only.

ETHICAL USE STATEMENT:
- This tool is for educational and research purposes only
- Do not use on networks you don't own or have explicit permission to monitor
- Respect privacy and data protection laws
- Do not capture sensitive information or personal data
- Use responsibly and ethically

Author: Educational Tool
License: Educational Use Only
"""

import socket
import struct
import textwrap
import binascii
import time
import argparse
import sys
import json
import csv
from datetime import datetime
from typing import Optional, List, Dict, Any, Pattern
import threading
import signal
import re
from collections import defaultdict, Counter

class EnhancedPacketSniffer:
    """Enhanced educational packet sniffer with advanced features."""
    
    def __init__(self, interface: Optional[str] = None, max_packets: int = 100, 
                 filters: Optional[List[str]] = None, log_file: Optional[str] = None,
                 verbose: bool = False):
        """
        Initialize the enhanced packet sniffer.
        
        Args:
            interface: Network interface to capture from
            max_packets: Maximum number of packets to capture
            filters: List of filter expressions
            log_file: File to log packet data
            verbose: Enable verbose output
        """
        self.interface = interface
        self.max_packets = max_packets
        self.filters = filters or []
        self.log_file = log_file
        self.verbose = verbose
        self.packet_count = 0
        self.running = False
        self.captured_packets = []
        self.statistics = {
            'protocols': Counter(),
            'source_ips': Counter(),
            'dest_ips': Counter(),
            'source_ports': Counter(),
            'dest_ports': Counter(),
            'total_bytes': 0,
            'packet_sizes': []
        }
        self.connections = defaultdict(list)
        
        # Initialize protocol mappings (same as basic version)
        self.protocols = {
            1: "ICMP", 6: "TCP", 17: "UDP", 8: "EGP", 9: "IGP",
            20: "HMP", 22: "IDP", 27: "RDP", 28: "IRTP", 29: "ISO-TP4",
            36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++",
            41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP",
            46: "RSVP", 47: "GRE", 50: "ESP", 51: "AH", 57: "SKIP",
            58: "IPv6-ICMP", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
            88: "EIGRP", 89: "OSPF", 93: "AX.25", 94: "IPIP",
            97: "ETHERIP", 98: "ENCAP", 103: "PIM", 108: "IPComp",
            112: "VRRP", 115: "L2TP", 124: "ISIS", 132: "SCTP",
            133: "FC", 135: "MPLS-in-IP", 136: "manet", 137: "HIP",
            138: "Shim6", 139: "WESP", 140: "ROHC"
        }
        
        # Enhanced port mappings
        self.tcp_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MongoDB",
            9200: "Elasticsearch", 11211: "Memcached"
        }
        
        self.udp_ports = {
            53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
            69: "TFTP", 123: "NTP", 161: "SNMP", 162: "SNMP-TRAP",
            514: "Syslog", 1194: "OpenVPN", 5353: "mDNS",
            1900: "SSDP", 5355: "LLMNR"
        }
        
        # Initialize logging
        if self.log_file:
            self.setup_logging()
        
        # Compile filters
        self.compiled_filters = self.compile_filters()
        
        print("=" * 70)
        print("ENHANCED PACKET SNIFFER - EDUCATIONAL TOOL")
        print("=" * 70)
        print("ETHICAL USE STATEMENT:")
        print("- This tool is for educational purposes only")
        print("- Only use on networks you own or have permission to monitor")
        print("- Respect privacy and data protection laws")
        print("- Do not capture sensitive or personal information")
        print("=" * 70)
        
        if self.filters:
            print(f"Active filters: {', '.join(self.filters)}")
        if self.log_file:
            print(f"Logging to: {self.log_file}")
        print("=" * 70)
    
    def setup_logging(self):
        """Setup logging configuration."""
        self.log_data = []
    
    def compile_filters(self) -> List[Any]:
        """Compile filter expressions into regex patterns or store protocol strings."""
        compiled = []
        for filter_expr in self.filters:
            try:
                if filter_expr.startswith('ip:'):
                    ip = filter_expr[3:]
                    pattern = re.compile(f"^{ip.replace('.', r'\.')}")
                    compiled.append(('ip', pattern))
                elif filter_expr.startswith('port:'):
                    port = filter_expr[5:]
                    pattern = re.compile(f"^{port}$")
                    compiled.append(('port', pattern))
                elif filter_expr.startswith('protocol:'):
                    proto = filter_expr[9:].upper()
                    compiled.append(('protocol', proto))
                else:
                    pattern = re.compile(filter_expr, re.IGNORECASE)
                    compiled.append(('general', pattern))
            except re.error:
                print(f"Warning: Invalid filter expression '{filter_expr}'")
        return compiled
    
    def apply_filters(self, packet_info: Dict[str, Any]) -> bool:
        """Apply filters to packet information."""
        if not self.compiled_filters:
            return True
        
        for filter_type, pattern in self.compiled_filters:
            if filter_type == 'ip':
                src_ip = packet_info.get('src_ip', '')
                dest_ip = packet_info.get('dest_ip', '')
                if not (pattern.search(src_ip) or pattern.search(dest_ip)):
                    return False
            elif filter_type == 'port':
                src_port = str(packet_info.get('src_port', ''))
                dest_port = str(packet_info.get('dest_port', ''))
                if not (pattern.search(src_port) or pattern.search(dest_port)):
                    return False
            elif filter_type == 'protocol':
                protocol = packet_info.get('protocol_name', '')
                if protocol != pattern:
                    return False
            elif filter_type == 'general':
                packet_str = str(packet_info)
                if not pattern.search(packet_str):
                    return False
        
        return True
    
    def main(self):
        """Main method to start packet capture."""
        try:
            # Create raw socket
            if sys.platform.startswith('win'):
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((self.interface or '', 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            print(f"\nStarting enhanced packet capture... (Max packets: {self.max_packets})")
            print("Press Ctrl+C to stop\n")
            
            self.running = True
            signal.signal(signal.SIGINT, self.signal_handler)
            
            # Start capture
            self.capture_packets()
            
        except PermissionError:
            print("ERROR: Permission denied. This tool requires administrator/root privileges.")
            print("Please run with appropriate permissions for educational purposes.")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: {e}")
            sys.exit(1)
        finally:
            self.cleanup()
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C to gracefully stop capture."""
        print("\n\nStopping packet capture...")
        self.running = False
    
    def cleanup(self):
        """Clean up resources and save logs."""
        if hasattr(self, 'sock'):
            if sys.platform.startswith('win'):
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sock.close()
        
        # Save logs if specified
        if self.log_file and self.log_data:
            self.save_logs()
        
        # Display enhanced summary
        self.display_enhanced_summary()
    
    def capture_packets(self):
        """Capture and analyze packets with enhanced features."""
        start_time = time.time()
        
        while self.running and self.packet_count < self.max_packets:
            try:
                raw_data, addr = self.sock.recvfrom(65535)
                self.packet_count += 1
                
                # Parse packet
                packet_info = self.parse_packet(raw_data, addr)
                
                # Apply filters
                if not self.apply_filters(packet_info):
                    continue
                
                # Update statistics
                self.update_statistics(packet_info)
                
                # Store packet
                self.captured_packets.append(packet_info)
                
                # Log packet if logging is enabled
                if self.log_file:
                    self.log_packet(packet_info)
                
                # Display packet
                self.display_enhanced_packet(packet_info)
                
                # Periodic statistics display
                if self.packet_count % 10 == 0:
                    self.display_periodic_stats(start_time)
                
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
    
    def parse_packet(self, raw_data: bytes, addr: tuple) -> Dict[str, Any]:
        """Parse raw packet data with enhanced analysis."""
        packet_info = {
            'timestamp': datetime.now(),
            'raw_data': raw_data,
            'addr': addr,
            'length': len(raw_data),
            'packet_num': self.packet_count
        }
        
        if sys.platform.startswith('win'):
            packet_info.update(self.parse_ip_header(raw_data))
        else:
            packet_info.update(self.parse_ethernet_frame(raw_data))
        
        # Enhanced analysis
        self.enhanced_analysis(packet_info)
        
        return packet_info
    
    def enhanced_analysis(self, packet_info: Dict[str, Any]):
        """Perform enhanced packet analysis."""
        # Protocol analysis
        if 'protocol' in packet_info:
            protocol_num = packet_info['protocol']
            packet_info['protocol_name'] = self.get_protocol_name(protocol_num)
            
            # Connection tracking
            if protocol_num in [6, 17]:  # TCP or UDP
                src_ip = packet_info.get('src_ip', '')
                dest_ip = packet_info.get('dest_ip', '')
                src_port = packet_info.get('src_port', 0)
                dest_port = packet_info.get('dest_port', 0)
                
                if src_ip and dest_ip:
                    connection_key = f"{src_ip}:{src_port}-{dest_ip}:{dest_port}"
                    packet_info['connection'] = connection_key
                    
                    # Track connection statistics
                    self.connections[connection_key].append({
                        'timestamp': packet_info['timestamp'],
                        'length': packet_info['length'],
                        'protocol': packet_info['protocol_name']
                    })
        
        # Payload analysis
        if 'payload' in packet_info and packet_info['payload']:
            payload = packet_info['payload']
            packet_info['payload_hex'] = binascii.hexlify(payload[:64]).decode('ascii')
            packet_info['payload_ascii'] = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload[:64])
            
            # Detect potential data patterns
            if len(payload) > 10:
                packet_info['data_pattern'] = self.analyze_data_pattern(payload)
    
    def analyze_data_pattern(self, payload: bytes) -> str:
        """Analyze payload for common data patterns."""
        if len(payload) < 4:
            return "Short"
        
        # Check for common patterns
        if payload.startswith(b'HTTP/'):
            return "HTTP"
        elif payload.startswith(b'GET ') or payload.startswith(b'POST '):
            return "HTTP Request"
        elif b'HTTP/1.' in payload or b'HTTP/2.' in payload:
            return "HTTP Response"
        elif payload.startswith(b'\x16\x03'):  # TLS handshake
            return "TLS"
        elif payload.startswith(b'\x17\x03'):  # TLS application data
            return "TLS Data"
        elif b'DNS' in payload[:10]:
            return "DNS"
        elif len(set(payload)) < len(payload) * 0.3:  # Low entropy
            return "Low Entropy"
        else:
            return "Binary Data"
    
    def update_statistics(self, packet_info: Dict[str, Any]):
        """Update capture statistics."""
        protocol = packet_info.get('protocol_name', 'Unknown')
        self.statistics['protocols'][protocol] += 1
        src_ip = packet_info.get('src_ip', '')
        dest_ip = packet_info.get('dest_ip', '')
        if src_ip:
            self.statistics['source_ips'][src_ip] += 1
        if dest_ip:
            self.statistics['dest_ips'][dest_ip] += 1
        src_port = packet_info.get('src_port')
        dest_port = packet_info.get('dest_port')
        if src_port:
            self.statistics['source_ports'][src_port] += 1
        if dest_port:
            self.statistics['dest_ports'][dest_port] += 1
        size = packet_info.get('length', 0)
        self.statistics['total_bytes'] += size
        self.statistics['packet_sizes'].append(size)
    
    def log_packet(self, packet_info: Dict[str, Any]):
        """Log packet information."""
        log_entry = {
            'timestamp': packet_info['timestamp'].isoformat(),
            'packet_num': packet_info['packet_num'],
            'length': packet_info['length'],
            'src_ip': packet_info.get('src_ip', ''),
            'dest_ip': packet_info.get('dest_ip', ''),
            'protocol': packet_info.get('protocol_name', ''),
            'src_port': packet_info.get('src_port', ''),
            'dest_port': packet_info.get('dest_port', ''),
            'connection': packet_info.get('connection', ''),
            'data_pattern': packet_info.get('data_pattern', '')
        }
        self.log_data.append(log_entry)
    
    def save_logs(self):
        """Save packet logs to file."""
        try:
            if not self.log_file:
                print("No log file specified.")
                return
            if self.log_file.endswith('.json'):
                with open(self.log_file, 'w') as f:
                    json.dump(self.log_data, f, indent=2)
            elif self.log_file.endswith('.csv'):
                with open(self.log_file, 'w', newline='') as f:
                    if self.log_data:
                        writer = csv.DictWriter(f, fieldnames=self.log_data[0].keys())
                        writer.writeheader()
                        writer.writerows(self.log_data)
            else:
                with open(self.log_file, 'w') as f:
                    for entry in self.log_data:
                        f.write(f"{entry}\n")
            
            print(f"Logs saved to: {self.log_file}")
        except Exception as e:
            print(f"Error saving logs: {e}")
    
    def display_enhanced_packet(self, packet_info: Dict[str, Any]):
        """Display enhanced packet information."""
        timestamp = packet_info['timestamp'].strftime('%H:%M:%S.%f')[:-3]
        
        print(f"\n{'='*70}")
        print(f"PACKET #{packet_info['packet_num']} - {timestamp}")
        print(f"{'='*70}")
        
        # Basic information
        print(f"Length: {packet_info['length']} bytes")
        
        # MAC addresses (if available)
        if 'src_mac' in packet_info:
            print(f"Source MAC:      {packet_info['src_mac']}")
            print(f"Destination MAC: {packet_info['dest_mac']}")
        
        # IP information
        if 'src_ip' in packet_info:
            print(f"Source IP:       {packet_info['src_ip']}")
            print(f"Destination IP:  {packet_info['dest_ip']}")
            print(f"Protocol:        {packet_info.get('protocol_name', 'Unknown')}")
            print(f"TTL:             {packet_info.get('ttl', 'N/A')}")
        
        # Protocol-specific information
        if packet_info.get('protocol') == 6:  # TCP
            self.display_tcp_info(packet_info)
        elif packet_info.get('protocol') == 17:  # UDP
            self.display_udp_info(packet_info)
        elif packet_info.get('protocol') == 1:  # ICMP
            self.display_icmp_info(packet_info)
        
        # Enhanced information
        if 'connection' in packet_info:
            print(f"Connection:      {packet_info['connection']}")
        
        if 'data_pattern' in packet_info:
            print(f"Data Pattern:    {packet_info['data_pattern']}")
        
        if 'payload_hex' in packet_info and self.verbose:
            print(f"Payload (hex):   {packet_info['payload_hex']}")
            print(f"Payload (ascii): {packet_info['payload_ascii']}")
        
        print(f"{'='*70}")
    
    def display_tcp_info(self, packet_info: Dict[str, Any]):
        """Display TCP-specific information."""
        tcp_info = self.parse_tcp_segment(packet_info['payload'])
        
        print(f"Source Port:     {tcp_info['src_port']} ({self.get_port_service(tcp_info['src_port'], 'TCP')})")
        print(f"Dest Port:       {tcp_info['dest_port']} ({self.get_port_service(tcp_info['dest_port'], 'TCP')})")
        print(f"Sequence:        {tcp_info['sequence']}")
        print(f"Acknowledgment:  {tcp_info['acknowledgment']}")
        
        flags = [k for k, v in tcp_info['flags'].items() if v]
        print(f"Flags:           {' '.join(flags)}")
        
        if tcp_info['payload']:
            print(f"Payload Size:    {len(tcp_info['payload'])} bytes")
    
    def display_udp_info(self, packet_info: Dict[str, Any]):
        """Display UDP-specific information."""
        udp_info = self.parse_udp_segment(packet_info['payload'])
        
        print(f"Source Port:     {udp_info['src_port']} ({self.get_port_service(udp_info['src_port'], 'UDP')})")
        print(f"Dest Port:       {udp_info['dest_port']} ({self.get_port_service(udp_info['dest_port'], 'UDP')})")
        print(f"Length:          {udp_info['size']} bytes")
        
        if udp_info['payload']:
            print(f"Payload Size:    {len(udp_info['payload'])} bytes")
    
    def display_icmp_info(self, packet_info: Dict[str, Any]):
        """Display ICMP-specific information."""
        icmp_info = self.parse_icmp_packet(packet_info['payload'])
        
        icmp_types = {
            0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
            8: "Echo Request", 11: "Time Exceeded", 13: "Timestamp",
            14: "Timestamp Reply", 17: "Address Mask Request", 18: "Address Mask Reply"
        }
        
        icmp_type = icmp_info['type']
        type_name = icmp_types.get(icmp_type, f"Unknown({icmp_type})")
        
        print(f"ICMP Type:       {icmp_type} ({type_name})")
        print(f"ICMP Code:       {icmp_info['code']}")
        print(f"Checksum:        {icmp_info['checksum']}")
        
        if icmp_info['payload']:
            print(f"Payload Size:    {len(icmp_info['payload'])} bytes")
    
    def display_periodic_stats(self, start_time: float):
        """Display periodic statistics."""
        elapsed = time.time() - start_time
        rate = self.packet_count / elapsed if elapsed > 0 else 0
        
        print(f"\n--- STATISTICS UPDATE ---")
        print(f"Packets captured: {self.packet_count}")
        print(f"Capture rate:     {rate:.2f} packets/sec")
        print(f"Total bytes:      {self.statistics['total_bytes']:,}")
        print(f"Elapsed time:     {elapsed:.1f} seconds")
        
        # Top protocols
        if self.statistics['protocols']:
            top_protocols = sorted(self.statistics['protocols'].items(), 
                                 key=lambda x: x[1], reverse=True)[:3]
            print(f"Top protocols:    {', '.join([f'{p}({c})' for p, c in top_protocols])}")
        
        print("---" * 20)
    
    def display_enhanced_summary(self):
        """Display enhanced capture summary."""
        print(f"\n{'='*70}")
        print("ENHANCED CAPTURE SUMMARY")
        print(f"{'='*70}")
        print(f"Total packets captured: {len(self.captured_packets)}")
        print(f"Total bytes captured:  {self.statistics['total_bytes']:,}")
        
        if self.statistics['packet_sizes']:
            avg_size = sum(self.statistics['packet_sizes']) / len(self.statistics['packet_sizes'])
            print(f"Average packet size:   {avg_size:.1f} bytes")
        
        if self.statistics['protocols']:
            print(f"\nProtocol Distribution:")
            for proto, count in sorted(self.statistics['protocols'].items(), 
                                     key=lambda x: x[1], reverse=True):
                percentage = (count / len(self.captured_packets)) * 100
                print(f"  {proto}: {count} packets ({percentage:.1f}%)")
        
        if self.statistics['source_ips']:
            print(f"\nTop Source IPs:")
            top_src = sorted(self.statistics['source_ips'].items(), 
                           key=lambda x: x[1], reverse=True)[:5]
            for ip, count in top_src:
                print(f"  {ip}: {count} packets")
        
        if self.connections:
            print(f"\nActive Connections: {len(self.connections)}")
            for conn, packets in list(self.connections.items())[:5]:
                print(f"  {conn}: {len(packets)} packets")
        
        print(f"\n{'='*70}")
        print("EDUCATIONAL INSIGHTS:")
        print("- Analyze traffic patterns for network optimization")
        print("- Identify potential security issues through traffic analysis")
        print("- Understand protocol behavior and network architecture")
        print("- Learn about network monitoring and troubleshooting")
        print(f"{'='*70}")
    
    # Inherit parsing methods from basic sniffer
    def parse_ethernet_frame(self, data: bytes) -> Dict[str, Any]:
        """Parse Ethernet frame header."""
        dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
        
        return {
            'dest_mac': self.format_mac(dest_mac),
            'src_mac': self.format_mac(src_mac),
            'eth_proto': socket.htons(eth_proto),
            'payload': data[14:]
        }
    
    def parse_ip_header(self, data: bytes) -> Dict[str, Any]:
        """Parse IP header."""
        version_header_len = data[0]
        version = version_header_len >> 4
        header_len = (version_header_len & 15) * 4
        
        ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        
        return {
            'version': version,
            'header_len': header_len,
            'ttl': ttl,
            'protocol': proto,
            'src_ip': self.format_ip(src),
            'dest_ip': self.format_ip(dest),
            'payload': data[header_len:]
        }
    
    def parse_tcp_segment(self, data: bytes) -> Dict[str, Any]:
        """Parse TCP segment."""
        (src_port, dest_port, sequence, acknowledgment, offset_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_flags >> 12) * 4
        flag_urg = (offset_flags & 32) >> 5
        flag_ack = (offset_flags & 16) >> 4
        flag_psh = (offset_flags & 8) >> 3
        flag_rst = (offset_flags & 4) >> 2
        flag_syn = (offset_flags & 2) >> 1
        flag_fin = offset_flags & 1
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'sequence': sequence,
            'acknowledgment': acknowledgment,
            'flags': {
                'URG': flag_urg,
                'ACK': flag_ack,
                'PSH': flag_psh,
                'RST': flag_rst,
                'SYN': flag_syn,
                'FIN': flag_fin
            },
            'payload': data[offset:]
        }
    
    def parse_udp_segment(self, data: bytes) -> Dict[str, Any]:
        """Parse UDP segment."""
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'size': size,
            'payload': data[8:]
        }
    
    def parse_icmp_packet(self, data: bytes) -> Dict[str, Any]:
        """Parse ICMP packet."""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        
        return {
            'type': icmp_type,
            'code': code,
            'checksum': checksum,
            'payload': data[4:]
        }
    
    def format_mac(self, mac_bytes: bytes) -> str:
        """Format MAC address."""
        return ':'.join(f'{b:02x}' for b in mac_bytes)
    
    def format_ip(self, ip_bytes: bytes) -> str:
        """Format IP address."""
        return '.'.join(str(b) for b in ip_bytes)
    
    def get_protocol_name(self, protocol_num: int) -> str:
        """Get protocol name from number."""
        return self.protocols.get(protocol_num, f"Unknown({protocol_num})")
    
    def get_port_service(self, port: int, protocol: str) -> str:
        """Get service name from port number."""
        if protocol == "TCP":
            return self.tcp_ports.get(port, f"Unknown({port})")
        elif protocol == "UDP":
            return self.udp_ports.get(port, f"Unknown({port})")
        return f"Unknown({port})"


def main():
    """Main function with enhanced argument parsing."""
    parser = argparse.ArgumentParser(
        description="Enhanced Educational Packet Sniffer Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ENHANCED FEATURES:
- Filtering by IP, port, or protocol
- Packet logging to JSON/CSV files
- Connection tracking and analysis
- Data pattern detection
- Enhanced statistics and reporting

ETHICAL USE STATEMENT:
This tool is for educational purposes only. Use responsibly and ethically.
Only monitor networks you own or have explicit permission to monitor.

Examples:
  python enhanced_sniffer.py                           # Basic capture
  python enhanced_sniffer.py -n 50                    # Capture 50 packets
  python enhanced_sniffer.py -f "ip:192.168.1"        # Filter by IP
  python enhanced_sniffer.py -f "port:80"             # Filter by port
  python enhanced_sniffer.py -l capture.json          # Log to JSON
  python enhanced_sniffer.py -v                       # Verbose output
        """
    )
    
    parser.add_argument(
        '-n', '--num-packets',
        type=int,
        default=100,
        help='Maximum number of packets to capture (default: 100)'
    )
    
    parser.add_argument(
        '-i', '--interface',
        type=str,
        default=None,
        help='Network interface to capture from (default: auto-detect)'
    )
    
    parser.add_argument(
        '-f', '--filter',
        action='append',
        type=str,
        help='Filter packets (ip:192.168.1, port:80, protocol:TCP)'
    )
    
    parser.add_argument(
        '-l', '--log-file',
        type=str,
        help='Log packets to file (supports .json, .csv, .txt)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output with payload details'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Enhanced Educational Packet Sniffer v2.0'
    )
    
    args = parser.parse_args()
    
    # Create and run enhanced sniffer
    sniffer = EnhancedPacketSniffer(
        interface=args.interface,
        max_packets=args.num_packets,
        filters=args.filter,
        log_file=args.log_file,
        verbose=args.verbose
    )
    
    try:
        sniffer.main()
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 