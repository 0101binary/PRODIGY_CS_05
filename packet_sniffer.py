#!/usr/bin/env python3
"""
Packet Sniffer Tool - Educational Version
=========================================

This tool is designed for educational purposes only. It captures and analyzes
network packets to help understand network protocols and traffic patterns.

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
from datetime import datetime
from typing import Dict, Any, Optional
import threading
import signal

class PacketSniffer:
    """Educational packet sniffer for network analysis."""
    
    def __init__(self, interface: Optional[str] = None, max_packets: int = 100):
        """
        Initialize the packet sniffer.
        
        Args:
            interface: Network interface to capture from (None for default)
            max_packets: Maximum number of packets to capture
        """
        self.interface = interface
        self.max_packets = max_packets
        self.packet_count = 0
        self.running = False
        self.captured_packets = []
        
        # Protocol mappings
        self.protocols = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP",
            8: "EGP",
            9: "IGP",
            20: "HMP",
            22: "IDP",
            27: "RDP",
            28: "IRTP",
            29: "ISO-TP4",
            36: "XTP",
            37: "DDP",
            38: "IDPR-CMTP",
            39: "TP++",
            41: "IPv6",
            43: "IPv6-Route",
            44: "IPv6-Frag",
            45: "IDRP",
            46: "RSVP",
            47: "GRE",
            50: "ESP",
            51: "AH",
            57: "SKIP",
            58: "IPv6-ICMP",
            59: "IPv6-NoNxt",
            60: "IPv6-Opts",
            88: "EIGRP",
            89: "OSPF",
            93: "AX.25",
            94: "IPIP",
            97: "ETHERIP",
            98: "ENCAP",
            103: "PIM",
            108: "IPComp",
            112: "VRRP",
            115: "L2TP",
            124: "ISIS",
            132: "SCTP",
            133: "FC",
            135: "MPLS-in-IP",
            136: "manet",
            137: "HIP",
            138: "Shim6",
            139: "WESP",
            140: "ROHC"
        }
        
        # TCP port mappings
        self.tcp_ports = {
            20: "FTP-DATA",
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-ALT",
            8443: "HTTPS-ALT"
        }
        
        # UDP port mappings
        self.udp_ports = {
            53: "DNS",
            67: "DHCP-Server",
            68: "DHCP-Client",
            69: "TFTP",
            123: "NTP",
            161: "SNMP",
            162: "SNMP-TRAP",
            514: "Syslog",
            1194: "OpenVPN",
            5353: "mDNS"
        }
        
        print("=" * 60)
        print("PACKET SNIFFER - EDUCATIONAL TOOL")
        print("=" * 60)
        print("ETHICAL USE STATEMENT:")
        print("- This tool is for educational purposes only")
        print("- Only use on networks you own or have permission to monitor")
        print("- Respect privacy and data protection laws")
        print("- Do not capture sensitive or personal information")
        print("=" * 60)
        
    def main(self):
        """Main method to start packet capture."""
        try:
            # Create raw socket
            if sys.platform.startswith('win'):
                # Windows implementation
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((self.interface or '', 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Unix/Linux implementation
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            print(f"\nStarting packet capture... (Max packets: {self.max_packets})")
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
        """Clean up resources."""
        if hasattr(self, 'sock'):
            if sys.platform.startswith('win'):
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sock.close()
        
        # Display summary
        self.display_summary()
    
    def capture_packets(self):
        """Capture and analyze packets."""
        while self.running and self.packet_count < self.max_packets:
            try:
                raw_data, addr = self.sock.recvfrom(65535)
                self.packet_count += 1
                
                # Parse and display packet
                packet_info = self.parse_packet(raw_data, addr)
                self.captured_packets.append(packet_info)
                self.display_packet(packet_info)
                
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
    
    def parse_packet(self, raw_data: bytes, addr: tuple) -> Dict[str, Any]:
        """Parse raw packet data and extract relevant information."""
        packet_info = {
            'timestamp': datetime.now(),
            'raw_data': raw_data,
            'addr': addr,
            'length': len(raw_data)
        }
        
        if sys.platform.startswith('win'):
            # Windows: Parse IP header directly
            packet_info.update(self.parse_ip_header(raw_data))
        else:
            # Unix/Linux: Parse Ethernet frame first
            packet_info.update(self.parse_ethernet_frame(raw_data))
        
        return packet_info
    
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
        # Version and header length
        version_header_len = data[0]
        version = version_header_len >> 4
        header_len = (version_header_len & 15) * 4
        
        # Extract IP header fields
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
    
    def format_payload(self, payload: bytes, max_bytes: int = 32) -> str:
        """Format payload data for display."""
        if len(payload) <= max_bytes:
            return binascii.hexlify(payload).decode('ascii')
        else:
            return binascii.hexlify(payload[:max_bytes]).decode('ascii') + '...'
    
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
    
    def display_packet(self, packet_info: Dict[str, Any]):
        """Display packet information in a formatted way."""
        timestamp = packet_info['timestamp'].strftime('%H:%M:%S.%f')[:-3]
        
        print(f"\n{'='*60}")
        print(f"PACKET #{packet_info.get('packet_num', self.packet_count)} - {timestamp}")
        print(f"{'='*60}")
        
        # Basic packet info
        print(f"Length: {packet_info['length']} bytes")
        
        # MAC addresses (if available)
        if 'src_mac' in packet_info:
            print(f"Source MAC:      {packet_info['src_mac']}")
            print(f"Destination MAC: {packet_info['dest_mac']}")
        
        # IP addresses
        if 'src_ip' in packet_info:
            print(f"Source IP:       {packet_info['src_ip']}")
            print(f"Destination IP:  {packet_info['dest_ip']}")
            print(f"Protocol:        {self.get_protocol_name(packet_info['protocol'])}")
            print(f"TTL:             {packet_info['ttl']}")
        
        # Protocol-specific information
        if packet_info.get('protocol') == 6:  # TCP
            tcp_info = self.parse_tcp_segment(packet_info['payload'])
            print(f"Source Port:     {tcp_info['src_port']} ({self.get_port_service(tcp_info['src_port'], 'TCP')})")
            print(f"Dest Port:       {tcp_info['dest_port']} ({self.get_port_service(tcp_info['dest_port'], 'TCP')})")
            print(f"Flags:           {' '.join([k for k, v in tcp_info['flags'].items() if v])}")
            
            if tcp_info['payload']:
                print(f"Payload:         {self.format_payload(tcp_info['payload'])}")
        
        elif packet_info.get('protocol') == 17:  # UDP
            udp_info = self.parse_udp_segment(packet_info['payload'])
            print(f"Source Port:     {udp_info['src_port']} ({self.get_port_service(udp_info['src_port'], 'UDP')})")
            print(f"Dest Port:       {udp_info['dest_port']} ({self.get_port_service(udp_info['dest_port'], 'UDP')})")
            print(f"Length:          {udp_info['size']} bytes")
            
            if udp_info['payload']:
                print(f"Payload:         {self.format_payload(udp_info['payload'])}")
        
        elif packet_info.get('protocol') == 1:  # ICMP
            icmp_info = self.parse_icmp_packet(packet_info['payload'])
            print(f"ICMP Type:       {icmp_info['type']}")
            print(f"ICMP Code:       {icmp_info['code']}")
            
            if icmp_info['payload']:
                print(f"Payload:         {self.format_payload(icmp_info['payload'])}")
        
        print(f"{'='*60}")
    
    def display_summary(self):
        """Display capture summary."""
        print(f"\n{'='*60}")
        print("CAPTURE SUMMARY")
        print(f"{'='*60}")
        print(f"Total packets captured: {len(self.captured_packets)}")
        print(f"Capture duration: {self.get_capture_duration()}")
        
        # Protocol statistics
        protocols = {}
        for packet in self.captured_packets:
            if 'protocol' in packet:
                proto = self.get_protocol_name(packet['protocol'])
                protocols[proto] = protocols.get(proto, 0) + 1
        
        if protocols:
            print("\nProtocol Distribution:")
            for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(self.captured_packets)) * 100
                print(f"  {proto}: {count} packets ({percentage:.1f}%)")
        
        print(f"\n{'='*60}")
        print("EDUCATIONAL NOTES:")
        print("- This tool demonstrates network packet analysis")
        print("- Understanding packet structure helps with network security")
        print("- Always use such tools ethically and legally")
        print("- Consider privacy implications of network monitoring")
        print(f"{'='*60}")

    def get_capture_duration(self) -> str:
        """Calculate and format capture duration."""
        if not self.captured_packets:
            return "0 seconds"
        
        start_time = self.captured_packets[0]['timestamp']
        end_time = self.captured_packets[-1]['timestamp']
        duration = end_time - start_time
        return f"{duration.total_seconds():.2f} seconds"


def main():
    """Main function with argument parsing."""
    parser = argparse.ArgumentParser(
        description="Educational Packet Sniffer Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ETHICAL USE STATEMENT:
This tool is for educational purposes only. Use responsibly and ethically.
Only monitor networks you own or have explicit permission to monitor.
Respect privacy and data protection laws.

Examples:
  python packet_sniffer.py                    # Default capture (100 packets)
  python packet_sniffer.py -n 50             # Capture 50 packets
  python packet_sniffer.py -i eth0           # Use specific interface
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
        '--version',
        action='version',
        version='Educational Packet Sniffer v1.0'
    )
    
    args = parser.parse_args()
    
    # Create and run sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        max_packets=args.num_packets
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