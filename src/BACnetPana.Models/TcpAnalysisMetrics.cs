using System;

namespace BACnetPana.Models
{
    /// <summary>
    /// Aggregierte TCP-Analysemetriken, gesammelt beim Einlesen der PCAP-Datei.
    /// </summary>
    public class TcpAnalysisMetrics
    {
        public int TotalTcpPackets { get; set; }
        public int Retransmissions { get; set; }
        public int FastRetransmissions { get; set; }
        public int DuplicateAcks { get; set; }
        public int Resets { get; set; }
        public int IcmpUnreachable { get; set; }
        public int LostSegments { get; set; }
        public int OutOfOrder { get; set; }
        public int WindowSizeZero { get; set; }
        public int KeepAlive { get; set; }

        /// <summary>
        /// Summe aller als Fehler gewerteten Ereignisse.
        /// </summary>
        public int GetLossEventsTotal()
        {
            // Alle TCP-Fehler zusammen
            return Retransmissions + FastRetransmissions + DuplicateAcks + IcmpUnreachable + Resets + LostSegments + OutOfOrder + WindowSizeZero + KeepAlive;
        }

        /// <summary>
        /// Prozentualer Anteil der Verlustereignisse an allen TCP-Paketen.
        /// </summary>
        public double GetLossPercent()
        {
            if (TotalTcpPackets <= 0)
                return 0.0;
            return (double)GetLossEventsTotal() * 100.0 / TotalTcpPackets;
        }
    }
}
