namespace bacneTPana.Models
{
    /// <summary>
    /// Repräsentiert ein einzelnes Netzwerkpaket aus einer PCAP/PCAPNG-Datei
    /// </summary>
    public class NetworkPacket
    {
        public int PacketNumber { get; set; }
        public DateTime Timestamp { get; set; }
        public long PacketLength { get; set; }

        // Layer 2 (Ethernet)
        public string? SourceMac { get; set; }
        public string? DestinationMac { get; set; }
        public string? EthernetType { get; set; }

        // Layer 3 (IP)
        public string? SourceIp { get; set; }
        public string? DestinationIp { get; set; }
        public string? Protocol { get; set; }
        public int Ttl { get; set; }

        // Layer 4 (Transport)
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }

        // Layer 7 (Application)
        public string? ApplicationProtocol { get; set; }

        // Payload
        public byte[]? RawData { get; set; }
        public string? HexData { get; set; }

        // Zusätzliche Informationen
        public string? Summary { get; set; }
        public Dictionary<string, string> Details { get; set; }

        // Fragmentierungsstatus
        public bool IsReassembled { get; set; }

        /// <summary>
        /// Gibt das anzuzeigende Protokoll zurück (bevorzugt ApplicationProtocol, sonst Protocol)
        /// </summary>
        public string DisplayProtocol => !string.IsNullOrEmpty(ApplicationProtocol)
            ? ApplicationProtocol
            : Protocol ?? "";

        public NetworkPacket()
        {
            Details = new Dictionary<string, string>();
        }

        public override string ToString()
        {
            var protocol = !string.IsNullOrEmpty(ApplicationProtocol)
                ? $"{Protocol}/{ApplicationProtocol}"
                : Protocol;
            return $"[{PacketNumber}] {Timestamp:HH:mm:ss.fff} {SourceIp}:{SourcePort} → {DestinationIp}:{DestinationPort} ({protocol})";
        }
    }
}
