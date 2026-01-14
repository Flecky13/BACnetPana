# BACnetPana - Network Analysis Software

![Alt text](images/APP.png)

## Network Analysis for BACnet & PCAP Files

**BACnetPana** analyzes PCAP files with focus on BACnet protocols.

### Key Features
- ✅ **Complete BACnet Analysis**: With TShark (Wireshark) all BACnet services, object types, and properties
- ✅ **PCAP File Analysis**: Support for Wireshark formats (.pcap, .pcapng, .cap)
- ✅ **Packet Inspection**: Detailed view of all OSI layers (Ethernet, IP, TCP/UDP, BACnet)
- ✅ **BACnet Database**: Automatic detection of devices, instance numbers, and vendor IDs
- ✅ **Real-time Statistics**: Automatic calculation of protocol, IP, and port statistics
- ✅ **Graphical Visualization**: Charts and statistics overview
- ✅ **Automatic Fallback**: Works without TShark (limited functionality)

---

## Requirements
- **.NET 8.0**
- **Wireshark** (recommended) - includes TShark for full BACnet analysis
  - Download: https://www.wireshark.org/download.html
- Without TShark: limited BACnet support via SharpPcap
