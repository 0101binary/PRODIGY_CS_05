# Educational Packet Sniffer Tool

A comprehensive network packet sniffer designed for educational purposes to help understand network protocols, traffic patterns, and network security concepts.

## ⚠️ ETHICAL USE STATEMENT

**This tool is for educational and research purposes only.**

### Important Guidelines:
- ✅ **DO** use on networks you own or have explicit permission to monitor
- ✅ **DO** use for learning network protocols and security concepts
- ✅ **DO** respect privacy and data protection laws
- ❌ **DO NOT** use on networks you don't own or have permission to monitor
- ❌ **DO NOT** capture sensitive information or personal data
- ❌ **DO NOT** use for malicious purposes

## 🚀 Features

### Core Functionality
- **Real-time packet capture** from network interfaces
- **Protocol analysis** (TCP, UDP, ICMP, and more)
- **Port and service identification** with common port mappings
- **Packet statistics** and distribution analysis
- **Educational output** with detailed packet information
- **Cross-platform support** (Windows, Linux, macOS)

### Educational Features
- **Detailed packet breakdown** showing headers and payloads
- **Protocol identification** with service name mappings
- **MAC and IP address formatting**
- **TCP flag analysis** (SYN, ACK, FIN, etc.)
- **Capture statistics** and summary reports
- **Ethical use reminders** throughout the tool

## 📋 Requirements

### System Requirements
- **Python 3.6+** (uses only standard library)
- **Administrator/Root privileges** (required for raw socket access)
- **Network interface** with active connection

### Optional Dependencies
For enhanced features, you can install:
```bash
pip install scapy>=2.4.5    # Advanced packet manipulation
pip install psutil>=5.8.0    # System utilities
pip install colorama>=0.4.4  # Colored output
```

## 🛠️ Installation

1. **Clone or download** the tool files
2. **Navigate** to the project directory
3. **Run with appropriate privileges**:

### Windows (Run as Administrator)
```powershell
python packet_sniffer.py
```

### Linux/macOS (Run with sudo)
```bash
sudo python3 packet_sniffer.py
```

## 📖 Usage

### Basic Usage
```bash
# Capture 100 packets (default)
python packet_sniffer.py

# Capture 50 packets
python packet_sniffer.py -n 50

# Use specific interface
python packet_sniffer.py -i eth0

# Show help
python packet_sniffer.py --help
```

### Command Line Options
- `-n, --num-packets`: Maximum packets to capture (default: 100)
- `-i, --interface`: Network interface to use (default: auto-detect)
- `--version`: Show version information
- `--help`: Show help message

## 📊 Sample Output

```
============================================================
PACKET SNIFFER - EDUCATIONAL TOOL
============================================================
ETHICAL USE STATEMENT:
- This tool is for educational purposes only
- Only use on networks you own or have permission to monitor
- Respect privacy and data protection laws
- Do not capture sensitive or personal information
============================================================

Starting packet capture... (Max packets: 100)
Press Ctrl+C to stop

============================================================
PACKET #1 - 14:30:25.123
============================================================
Length: 74 bytes
Source MAC:      00:11:22:33:44:55
Destination MAC: aa:bb:cc:dd:ee:ff
Source IP:       192.168.1.100
Destination IP:  8.8.8.8
Protocol:        TCP
TTL:             64
Source Port:     54321 (Unknown(54321))
Dest Port:       53 (DNS)
Flags:           PSH ACK
Payload:         0100000100000000000000...
============================================================
```

## 🔍 What You'll Learn

### Network Concepts
- **Packet structure** and header analysis
- **Protocol identification** and behavior
- **Port and service mapping**
- **TCP connection states** and flags
- **Network traffic patterns**

### Security Insights
- **Traffic analysis** techniques
- **Protocol vulnerabilities** understanding
- **Network monitoring** best practices
- **Privacy considerations** in networking

## 🛡️ Security and Privacy

### Built-in Protections
- **Educational focus** with clear ethical guidelines
- **Limited payload display** to prevent sensitive data exposure
- **No data logging** or persistent storage
- **Real-time analysis** only

### Best Practices
- **Use on test networks** or your own infrastructure
- **Respect network policies** and terms of service
- **Understand local laws** regarding network monitoring
- **Consider privacy implications** of packet analysis

## 🐛 Troubleshooting

### Common Issues

**Permission Denied Error:**
```
ERROR: Permission denied. This tool requires administrator/root privileges.
```
**Solution:** Run with administrator/root privileges

**No Packets Captured:**
- Check if network interface is active
- Verify firewall settings
- Ensure you have network traffic

**Interface Not Found:**
- Use `-i` flag to specify correct interface
- Check available interfaces with system tools

## 📚 Educational Resources

### Related Topics
- **Network Protocols** (TCP/IP, UDP, ICMP)
- **Network Security** and monitoring
- **Packet Analysis** techniques
- **Privacy and Ethics** in networking

### Further Learning
- Wireshark (professional packet analyzer)
- Network security courses
- Ethical hacking certifications
- Network administration training

## 🤝 Contributing

This is an educational tool. Contributions should focus on:
- **Educational value** and learning outcomes
- **Ethical use** and responsible development
- **Code clarity** and documentation
- **Security best practices**

## 📄 License

This tool is provided for educational purposes only. Use responsibly and ethically.

## ⚖️ Legal Disclaimer

This tool is for educational purposes only. Users are responsible for:
- Complying with local laws and regulations
- Respecting network policies and terms of service
- Using the tool ethically and responsibly
- Not using for malicious or unauthorized purposes

The developers are not responsible for misuse of this tool.

---

**Remember: With great power comes great responsibility. Use this tool to learn, not to harm.** 