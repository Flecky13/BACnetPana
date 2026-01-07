using System;
using System.Collections.Generic;

namespace BACnetPana.Models
{
    /// <summary>
    /// Statistiken für Netzwerkverkehr-Analyse
    /// </summary>
    public class PacketStatistics
    {
        public int TotalPackets { get; set; }
        public long TotalBytes { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }

        // Protokoll-Statistiken
        public Dictionary<string, int> ProtocolCount { get; set; }
        public Dictionary<string, long> ProtocolBytes { get; set; }

        // Hierarchische Protokoll-Statistiken (z.B. "UDP/BACnet", "TCP/HTTP")
        public Dictionary<string, int> HierarchicalProtocolCount { get; set; }
        public Dictionary<string, long> HierarchicalProtocolBytes { get; set; }

        // IP-Statistiken
        public Dictionary<string, int> IpSourceCount { get; set; }
        public Dictionary<string, int> IpDestinationCount { get; set; }

        // Port-Statistiken
        public Dictionary<int, int> SourcePortCount { get; set; }
        public Dictionary<int, int> DestinationPortCount { get; set; }

        // Zeitbasierte Statistiken
        public Dictionary<DateTime, int> PacketsPerSecond { get; set; }
        public Dictionary<DateTime, long> BytesPerSecond { get; set; }

        public PacketStatistics()
        {
            ProtocolCount = new Dictionary<string, int>();
            ProtocolBytes = new Dictionary<string, long>();
            HierarchicalProtocolCount = new Dictionary<string, int>();
            HierarchicalProtocolBytes = new Dictionary<string, long>();
            IpSourceCount = new Dictionary<string, int>();
            IpDestinationCount = new Dictionary<string, int>();
            SourcePortCount = new Dictionary<int, int>();
            DestinationPortCount = new Dictionary<int, int>();
            PacketsPerSecond = new Dictionary<DateTime, int>();
            BytesPerSecond = new Dictionary<DateTime, long>();
        }

        public double GetAveragePacketSize()
        {
            return TotalPackets > 0 ? (double)TotalBytes / TotalPackets : 0;
        }

        public double GetDurationSeconds()
        {
            return (EndTime - StartTime).TotalSeconds;
        }

        public double GetPacketsPerSecond()
        {
            var duration = GetDurationSeconds();
            return duration > 0 ? TotalPackets / duration : 0;
        }

        public double GetMegabitsPerSecond()
        {
            var duration = GetDurationSeconds();
            return duration > 0 ? (TotalBytes * 8) / (duration * 1000000) : 0;
        }
    }
}
