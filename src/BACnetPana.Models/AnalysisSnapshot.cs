using System;
using System.Collections.Generic;

namespace bacneTPana.Models
{
    /// <summary>
    /// Repräsentiert einen gespeicherten Analysezustand
    /// Kann serialisiert und gespeichert werden, um einen Import zu vermeiden
    /// </summary>
    public class AnalysisSnapshot
    {
        public string Version { get; set; } = "1.0";
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public string? OriginalPcapFile { get; set; }

        // Paketdaten
        public List<NetworkPacket> Packets { get; set; } = new List<NetworkPacket>();

        // Statistiken
        public PacketStatistics? Statistics { get; set; }

        // BACnet-Datenbank
        public BACnetDatabaseSnapshot? BacnetDb { get; set; }

        /// <summary>
        /// Vereinfachte Darstellung der BACnetDatabase für Serialisierung
        /// </summary>
        public class BACnetDatabaseSnapshot
        {
            public Dictionary<string, string> IpToInstance { get; set; } = new Dictionary<string, string>();
            public Dictionary<string, string> IpToDeviceName { get; set; } = new Dictionary<string, string>();
            public Dictionary<string, string> IpToVendorId { get; set; } = new Dictionary<string, string>();
            public TcpAnalysisMetrics? TcpMetrics { get; set; }

            public static BACnetDatabaseSnapshot FromBACnetDatabase(BACnetDatabase db)
            {
                return new BACnetDatabaseSnapshot
                {
                    IpToInstance = new Dictionary<string, string>(db.IpToInstance),
                    IpToDeviceName = new Dictionary<string, string>(db.IpToDeviceName),
                    IpToVendorId = new Dictionary<string, string>(db.IpToVendorId),
                    TcpMetrics = db.TcpMetrics
                };
            }

            public BACnetDatabase ToBACnetDatabase()
            {
                var db = new BACnetDatabase();
                foreach (var kvp in IpToInstance)
                    db.IpToInstance[kvp.Key] = kvp.Value;
                foreach (var kvp in IpToDeviceName)
                    db.IpToDeviceName[kvp.Key] = kvp.Value;
                foreach (var kvp in IpToVendorId)
                    db.IpToVendorId[kvp.Key] = kvp.Value;

                if (TcpMetrics != null)
                {
                    db.TcpMetrics.Retransmissions = TcpMetrics.Retransmissions;
                    db.TcpMetrics.FastRetransmissions = TcpMetrics.FastRetransmissions;
                    db.TcpMetrics.DuplicateAcks = TcpMetrics.DuplicateAcks;
                    db.TcpMetrics.LostSegments = TcpMetrics.LostSegments;
                    db.TcpMetrics.Resets = TcpMetrics.Resets;
                    db.TcpMetrics.IcmpUnreachable = TcpMetrics.IcmpUnreachable;
                    db.TcpMetrics.TotalTcpPackets = TcpMetrics.TotalTcpPackets;
                }

                return db;
            }
        }
    }
}
