using System;
using System.Collections.Generic;
using System.Linq;
using BACnetPana.Models;

namespace BACnetPana.DataAccess
{
    /// <summary>
    /// Handles statistics calculation for packet data
    /// </summary>
    public class StatisticsCalculator
    {
        public PacketStatistics CalculateStatistics(List<NetworkPacket> packets)
        {
            var stats = new PacketStatistics();

            // Filtere reassemblierte Pakete aus
            var completePackets = packets.Where(p => !p.IsReassembled).ToList();

            if (completePackets.Count == 0)
                return stats;

            stats.TotalPackets = completePackets.Count;
            stats.TotalBytes = completePackets.Sum(p => p.PacketLength);
            stats.StartTime = completePackets.Min(p => p.Timestamp);
            stats.EndTime = completePackets.Max(p => p.Timestamp);

            // Protokoll-Statistiken
            foreach (var packet in completePackets)
            {
                // Basis-Protokoll (Layer 3/4: UDP, TCP, ICMP, etc.)
                var baseProtocol = packet.Protocol ?? "Unknown";

                if (!stats.ProtocolCount.ContainsKey(baseProtocol))
                    stats.ProtocolCount[baseProtocol] = 0;
                stats.ProtocolCount[baseProtocol]++;

                if (!stats.ProtocolBytes.ContainsKey(baseProtocol))
                    stats.ProtocolBytes[baseProtocol] = 0;
                stats.ProtocolBytes[baseProtocol] += packet.PacketLength;

                // Hierarchische Protokoll-Statistiken (inkl. Application Layer)
                string hierarchicalKey;

                if (!string.IsNullOrEmpty(packet.ApplicationProtocol))
                {
                    // Hat Application Protocol: z.B. "UDP/BACnet", "TCP/HTTP"
                    hierarchicalKey = $"{baseProtocol}/{packet.ApplicationProtocol}";
                }
                else
                {
                    // Nur Transport-Protokoll: z.B. "UDP", "TCP", "ICMP"
                    hierarchicalKey = baseProtocol;
                }

                if (!stats.HierarchicalProtocolCount.ContainsKey(hierarchicalKey))
                    stats.HierarchicalProtocolCount[hierarchicalKey] = 0;
                stats.HierarchicalProtocolCount[hierarchicalKey]++;

                if (!stats.HierarchicalProtocolBytes.ContainsKey(hierarchicalKey))
                    stats.HierarchicalProtocolBytes[hierarchicalKey] = 0;
                stats.HierarchicalProtocolBytes[hierarchicalKey] += packet.PacketLength;
            }

            // IP-Statistiken
            foreach (var packet in completePackets.Where(p => !string.IsNullOrEmpty(p.SourceIp)))
            {
                var sourceIp = packet.SourceIp!;
                var destinationIp = packet.DestinationIp ?? "Unknown";

                if (!stats.IpSourceCount.ContainsKey(sourceIp))
                    stats.IpSourceCount[sourceIp] = 0;
                stats.IpSourceCount[sourceIp]++;

                if (!stats.IpDestinationCount.ContainsKey(destinationIp))
                    stats.IpDestinationCount[destinationIp] = 0;
                stats.IpDestinationCount[destinationIp]++;
            }

            // Port-Statistiken
            foreach (var packet in completePackets.Where(p => p.SourcePort > 0))
            {
                if (!stats.SourcePortCount.ContainsKey(packet.SourcePort))
                    stats.SourcePortCount[packet.SourcePort] = 0;
                stats.SourcePortCount[packet.SourcePort]++;

                if (!stats.DestinationPortCount.ContainsKey(packet.DestinationPort))
                    stats.DestinationPortCount[packet.DestinationPort] = 0;
                stats.DestinationPortCount[packet.DestinationPort]++;
            }

            // Zeitbasierte Statistiken
            // Zeitbasierte Statistiken - 5-Minuten-Binning für bessere Aggregation
            foreach (var packet in completePackets)
            {
                // Runde auf nächste 5-Minuten Grenze
                var totalSeconds = (long)packet.Timestamp.TimeOfDay.TotalSeconds;
                var binSize = 5 * 60; // 5 Minuten
                var binnedSeconds = (totalSeconds / binSize) * binSize;
                var timeKey = packet.Timestamp.Date.AddSeconds(binnedSeconds);

                if (!stats.PacketsPerSecond.ContainsKey(timeKey))
                    stats.PacketsPerSecond[timeKey] = 0;
                stats.PacketsPerSecond[timeKey]++;

                if (!stats.BytesPerSecond.ContainsKey(timeKey))
                    stats.BytesPerSecond[timeKey] = 0;
                stats.BytesPerSecond[timeKey] += packet.PacketLength;
            }

            return stats;
        }

        public Dictionary<string, int> GetProtocolDistribution(List<NetworkPacket> packets)
        {
            return packets
                .Where(p => !string.IsNullOrEmpty(p.Protocol))
                .GroupBy(p => p.Protocol!)
                .ToDictionary(g => g.Key, g => g.Count());
        }

        public Dictionary<string, long> GetTopSourceIps(List<NetworkPacket> packets, int topCount = 10)
        {
            return packets
                .Where(p => !string.IsNullOrEmpty(p.SourceIp))
                .GroupBy(p => p.SourceIp!)
                .OrderByDescending(g => g.Count())
                .Take(topCount)
                .ToDictionary(g => g.Key, g => (long)g.Sum(p => p.PacketLength));
        }

        public Dictionary<string, long> GetTopDestinationIps(List<NetworkPacket> packets, int topCount = 10)
        {
            return packets
                .Where(p => !string.IsNullOrEmpty(p.DestinationIp))
                .GroupBy(p => p.DestinationIp!)
                .OrderByDescending(g => g.Count())
                .Take(topCount)
                .ToDictionary(g => g.Key, g => (long)g.Sum(p => p.PacketLength));
        }

        public Dictionary<int, int> GetTopPorts(List<NetworkPacket> packets, int topCount = 10)
        {
            var portCount = new Dictionary<int, int>();

            foreach (var packet in packets.Where(p => p.SourcePort > 0 || p.DestinationPort > 0))
            {
                if (packet.SourcePort > 0)
                {
                    if (!portCount.ContainsKey(packet.SourcePort))
                        portCount[packet.SourcePort] = 0;
                    portCount[packet.SourcePort]++;
                }

                if (packet.DestinationPort > 0)
                {
                    if (!portCount.ContainsKey(packet.DestinationPort))
                        portCount[packet.DestinationPort] = 0;
                    portCount[packet.DestinationPort]++;
                }
            }

            return portCount
                .OrderByDescending(p => p.Value)
                .Take(topCount)
                .ToDictionary(p => p.Key, p => p.Value);
        }
    }
}
