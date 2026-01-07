using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using BACnetPana.Models;

namespace BACnetPana.DataAccess
{
    /// <summary>
    /// Responsible for parsing and reading PCAP/PCAPNG files (Wireshark format)
    /// Supports both .pcap and .pcapng file formats
    /// </summary>
    public class PcapFileReader : IPcapParser
    {
        public event EventHandler<PacketReadEventArgs>? PacketRead;
        public event EventHandler<string>? ProgressChanged;

        // BACnet-Datenbasis wird während des Einlesens aufgebaut
        public BACnetDatabase BACnetDb { get; private set; } = new BACnetDatabase();

        public async Task<List<NetworkPacket>> ReadPcapFileAsync(string filePath)
        {
            return await Task.Run(() => ReadPcapFile(filePath));
        }

        public List<NetworkPacket> ReadPcapFile(string filePath)
        {
            var packets = new List<NetworkPacket>();
            BACnetDb = new BACnetDatabase(); // Reset bei jedem neuen File

            try
            {
                var device = new CaptureFileReaderDevice(filePath);
                device.Open();

                // Zähle zuerst die Gesamtanzahl der Pakete für Progress
                int totalPackets = 0;
                PacketCapture capture;
                while (device.GetNextPacket(out capture) == GetPacketStatus.PacketRead)
                {
                    totalPackets++;
                }

                // Reset device für das eigentliche Lesen
                device.Close();
                device = new CaptureFileReaderDevice(filePath);
                device.Open();

                int packetCount = 0;

                while (device.GetNextPacket(out capture) == GetPacketStatus.PacketRead)
                {
                    packetCount++;

                    try
                    {
                        var packet = PacketDotNet.Packet.ParsePacket(LinkLayers.Ethernet, capture.Data.ToArray());
                        if (packet != null)
                        {
                            // Extrahiere den Timestamp aus der Capture
                            var dt = capture.Header.Timeval.Date;

                            NetworkPacket networkPacket = ParsePacket(packet, packetCount, dt);
                            packets.Add(networkPacket);

                            // Verarbeite BACnet-Informationen während des Einlesens
                            BACnetDb.ProcessPacket(networkPacket);

                            PacketRead?.Invoke(this, new PacketReadEventArgs { Packet = networkPacket, TotalPackets = packetCount });

                            // Melde Fortschritt alle 5000 Pakete
                            if (packetCount % 5000 == 0 || packetCount == totalPackets)
                            {
                                int progressPercent = totalPackets > 0 ? (packetCount * 100 / totalPackets) : 0;
                                ProgressChanged?.Invoke(this, $"Gelesen: {packetCount} von {totalPackets} Paketen ({progressPercent}%)");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        ProgressChanged?.Invoke(this, $"Warnung beim Parsen von Paket {packetCount}: {ex.Message}");
                    }
                }

                device.Close();
                ProgressChanged?.Invoke(this, $"Fertig: {packetCount} Pakete gelesen");
                ProgressChanged?.Invoke(this, BACnetDb.GetSummary());
            }
            catch (Exception ex)
            {
                ProgressChanged?.Invoke(this, $"Fehler beim Lesen der Datei: {ex.Message}");
            }

            return packets;
        }

        private NetworkPacket ParsePacket(PacketDotNet.Packet packet, int packetNumber, DateTime timestamp)
        {
            var networkPacket = new NetworkPacket
            {
                PacketNumber = packetNumber,
                Timestamp = timestamp,
                PacketLength = packet.TotalPacketLength,
                RawData = packet.Bytes,
                HexData = BitConverter.ToString(packet.Bytes).Replace("-", " ")
            };

            try
            {
                // Parse Ethernet Frame (Layer 2)
                var ethernetPacket = packet.Extract<EthernetPacket>();
                if (ethernetPacket != null)
                {
                    networkPacket.SourceMac = ethernetPacket.SourceHardwareAddress.ToString();
                    networkPacket.DestinationMac = ethernetPacket.DestinationHardwareAddress.ToString();
                    networkPacket.EthernetType = ethernetPacket.Type.ToString();

                    // Parse ARP Packet (Layer 2.5)
                    var arpPacket = packet.Extract<ArpPacket>();
                    if (arpPacket != null)
                    {
                        networkPacket.Protocol = "Arp";
                        networkPacket.SourceIp = arpPacket.SenderProtocolAddress?.ToString() ?? "";
                        networkPacket.DestinationIp = arpPacket.TargetProtocolAddress?.ToString() ?? "";
                        networkPacket.Details["ARP Operation"] = arpPacket.Operation.ToString();
                        networkPacket.Details["Sender MAC"] = arpPacket.SenderHardwareAddress.ToString();
                        networkPacket.Details["Target MAC"] = arpPacket.TargetHardwareAddress.ToString();
                        networkPacket.IsReassembled = false;
                        return networkPacket;
                    }
                }

                // Parse IP Packet (Layer 3)
                var ipv4Packet = packet.Extract<IPv4Packet>();
                if (ipv4Packet != null)
                {
                    networkPacket.SourceIp = ipv4Packet.SourceAddress.ToString();
                    networkPacket.DestinationIp = ipv4Packet.DestinationAddress.ToString();
                    networkPacket.Protocol = ipv4Packet.Protocol.ToString();
                    networkPacket.Ttl = ipv4Packet.TimeToLive;

                    // Prüfe ob Paket fragmentiert ist:
                    // - Fragment Offset > 0 bedeutet, dass dies nicht das erste Fragment ist
                    // - More Fragments Flag (0x2000) bedeutet, dass weitere Fragmente folgen
                    // Ein reassembled Paket hat FragmentOffset > 0
                    networkPacket.IsReassembled = ipv4Packet.FragmentOffset > 0;
                }
                else
                {
                    var ipv6Packet = packet.Extract<IPv6Packet>();
                    if (ipv6Packet != null)
                    {
                        networkPacket.SourceIp = ipv6Packet.SourceAddress.ToString();
                        networkPacket.DestinationIp = ipv6Packet.DestinationAddress.ToString();
                        networkPacket.Protocol = ipv6Packet.NextHeader.ToString();
                        networkPacket.IsReassembled = false;
                    }
                }

                // Parse TCP Packet (Layer 4)
                var tcpPacket = packet.Extract<TcpPacket>();
                if (tcpPacket != null)
                {
                    networkPacket.SourcePort = tcpPacket.SourcePort;
                    networkPacket.DestinationPort = tcpPacket.DestinationPort;
                    networkPacket.Details["TCP Flags"] = FormatTcpFlags(tcpPacket);
                    networkPacket.Details["Sequence"] = tcpPacket.SequenceNumber.ToString();
                    networkPacket.Details["Acknowledgment"] = tcpPacket.AcknowledgmentNumber.ToString();
                }
                else
                {
                    // Parse UDP Packet (Layer 4)
                    var udpPacket = packet.Extract<UdpPacket>();
                    if (udpPacket != null)
                    {
                        networkPacket.SourcePort = udpPacket.SourcePort;
                        networkPacket.DestinationPort = udpPacket.DestinationPort;
                    }
                    else if (networkPacket.Protocol == "Udp")
                    {
                        // Fallback: Versuche UDP-Ports manuell aus Raw-Bytes zu lesen
                        // UDP-Header: Source Port (2 bytes) | Dest Port (2 bytes) | Length (2 bytes) | Checksum (2 bytes)
                        try
                        {
                            var ipPacket = packet.Extract<IPv4Packet>();
                            if (ipPacket != null && ipPacket.PayloadData != null && ipPacket.PayloadData.Length >= 4)
                            {
                                var udpData = ipPacket.PayloadData;
                                networkPacket.SourcePort = (udpData[0] << 8) | udpData[1];
                                networkPacket.DestinationPort = (udpData[2] << 8) | udpData[3];
                            }
                        }
                        catch
                        {
                            // Ignoriere Fehler beim manuellen Parsen
                        }
                    }
                }

                // Parse ICMP Packet
                var icmpPacket = packet.Extract<IcmpV4Packet>();
                if (icmpPacket != null)
                {
                    networkPacket.Details["ICMP Type"] = icmpPacket.TypeCode.ToString();
                }

                // Erkenne Application-Layer-Protokoll
                networkPacket.ApplicationProtocol = ProtocolInfo.DetectApplicationProtocol(
                    networkPacket.Protocol ?? "",
                    networkPacket.SourcePort,
                    networkPacket.DestinationPort,
                    networkPacket.RawData
                );
            }
            catch (Exception)
            {
                // Continue processing even if extraction fails - silent
            }

            networkPacket.Summary = networkPacket.ToString();
            return networkPacket;
        }

        private string FormatTcpFlags(TcpPacket tcpPacket)
        {
            var flags = new List<string>();

            ushort flagWord = tcpPacket.Flags;
            if ((flagWord & 0x01) != 0) flags.Add("FIN");
            if ((flagWord & 0x02) != 0) flags.Add("SYN");
            if ((flagWord & 0x04) != 0) flags.Add("RST");
            if ((flagWord & 0x08) != 0) flags.Add("PSH");
            if ((flagWord & 0x10) != 0) flags.Add("ACK");
            if ((flagWord & 0x20) != 0) flags.Add("URG");

            return flags.Count > 0 ? string.Join(", ", flags) : "NONE";
        }
    }

    public class PacketReadEventArgs : EventArgs
    {
        public NetworkPacket? Packet { get; set; }
        public int TotalPackets { get; set; }
    }
}
