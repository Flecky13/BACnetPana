using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace BACnetPana.Models
{
    /// <summary>
    /// Datenbasis für BACnet-Informationen, aufgebaut während des PCAP-Einlesens
    /// </summary>
    public class BACnetDatabase
    {
        // Mapping: IP-Adresse -> BACnet-Instanznummer
        public Dictionary<string, string> IpToInstance { get; } = new Dictionary<string, string>();

        // Mapping: IP-Adresse -> Device-Name
        public Dictionary<string, string> IpToDeviceName { get; } = new Dictionary<string, string>();

        // Mapping: IP-Adresse -> Vendor-ID
        public Dictionary<string, string> IpToVendorId { get; } = new Dictionary<string, string>();

        // Debug-Zähler
        private int _totalPacketsProcessed = 0;
        private int _bacnetPacketsFound = 0;
        private int _bacnetByApplicationProtocol = 0;
        private int _bacnetByDestPort = 0;
        private int _bacnetBySourcePort = 0;
        private int _packetsWithDetails = 0;

        // TCP-Analysemetriken
        public TcpAnalysisMetrics TcpMetrics { get; } = new TcpAnalysisMetrics();

        /// <summary>
        /// Extrahiert BACnet-Instanznummer aus typischen Feldern wie
        /// "device,12345", "device 12345" oder beliebigen Strings mit Zahlen
        /// </summary>
        public static string ExtractInstanceNumber(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;
            var digits = new string(input.Where(char.IsDigit).ToArray());
            return digits;
        }

        /// <summary>
        /// Verarbeitet ein einzelnes Paket und extrahiert BACnet-Informationen
        /// </summary>
        public void ProcessPacket(NetworkPacket packet)
        {
            _totalPacketsProcessed++;

            // Erkenne BACnet-Pakete mit der GLEICHEN Logik wie in AnalysisWindow!
            // 3-Teil-Filter: ApplicationProtocol ODER Destination-Port ODER Source-Port
            bool isApplicationProtocolBACnet = packet.ApplicationProtocol?.ToUpper() == "BACNET";
            bool isDestPortBACnet = packet.DestinationPort >= 47808 && packet.DestinationPort <= 47823;
            bool isSrcPortBACnet = packet.SourcePort >= 47808 && packet.SourcePort <= 47823;

            bool isBACnet = isApplicationProtocolBACnet || isDestPortBACnet || isSrcPortBACnet;

            if (!isBACnet)
                return;

            // Zähle was erkannt wurde
            if (isApplicationProtocolBACnet) _bacnetByApplicationProtocol++;
            if (isDestPortBACnet) _bacnetByDestPort++;
            if (isSrcPortBACnet) _bacnetBySourcePort++;

            if (packet.Details == null || packet.Details.Count == 0)
            {
                return;
            }

            _bacnetPacketsFound++;
            _packetsWithDetails++;

            var sourceIp = string.IsNullOrWhiteSpace(packet.SourceIp) ? "Unbekannt" : packet.SourceIp;
            string? instanceCandidate = null;
            string? deviceNameCandidate = null;
            string? vendorIdCandidate = null;

            foreach (var detail in packet.Details)
            {
                var key = detail.Key?.ToLower() ?? string.Empty;
                var rawValue = detail.Value ?? string.Empty;
                var valueLower = rawValue.ToLower();

                // Suche nach Instanznummer in verschiedenen Feldern
                if (instanceCandidate == null)
                {
                    if (key.Contains("objectidentifier") ||
                        key.Contains("device_instance") ||
                        key.Contains("object_instance") ||
                        key.Contains("instance"))
                    {
                        var parsed = ExtractInstanceNumber(rawValue);
                        if (!string.IsNullOrEmpty(parsed))
                            instanceCandidate = parsed;
                    }
                }

                // Suche nach Device-Namen
                if (deviceNameCandidate == null)
                {
                    if (key.Contains("object_name") || key.Contains("device_name") || key.Contains("name"))
                    {
                        if (!string.IsNullOrWhiteSpace(rawValue) && rawValue.Length > 1)
                            deviceNameCandidate = rawValue.Trim();
                    }
                }

                // Suche nach Vendor-ID
                if (vendorIdCandidate == null)
                {
                    if (key.Contains("vendor"))
                    {
                        if (!string.IsNullOrWhiteSpace(rawValue))
                            vendorIdCandidate = rawValue.Trim();
                    }
                }
            }

            // Speichere Instanznummer wenn gefunden (bevorzugt von I-Am Paketen)
            if (!string.IsNullOrEmpty(instanceCandidate))
            {
                if (!IpToInstance.ContainsKey(sourceIp))
                {
                    IpToInstance[sourceIp] = instanceCandidate;
                }
            }

            // Speichere Device-Namen (unabhängig von I-Am)
            if (!string.IsNullOrEmpty(deviceNameCandidate))
            {
                if (!IpToDeviceName.ContainsKey(sourceIp))
                    IpToDeviceName[sourceIp] = deviceNameCandidate;
            }

            // Speichere Vendor-ID (unabhängig von I-Am)
            if (!string.IsNullOrEmpty(vendorIdCandidate))
            {
                if (!IpToVendorId.ContainsKey(sourceIp))
                    IpToVendorId[sourceIp] = vendorIdCandidate;
            }
        }

        /// <summary>
        /// Verarbeitet allgemeine TCP/ICMP Felder für Verlustmetriken.
        /// Wird beim Einlesen jedes Pakets aufgerufen.
        /// </summary>
        public void ProcessTcpFields(NetworkPacket packet)
        {
            if (packet == null)
                return;

            // Zähle Gesamtzahl TCP-Pakete
            if (string.Equals(packet.Protocol, "TCP", StringComparison.OrdinalIgnoreCase))
            {
                TcpMetrics.TotalTcpPackets++;
            }

            // ICMP Destination Unreachable
            if (string.Equals(packet.Protocol, "ICMP", StringComparison.OrdinalIgnoreCase) && packet.Details != null)
            {
                if (packet.Details.TryGetValue("ICMP Type", out var icmpType))
                {
                    // TShark/PacketDotNet liefern oft z.B. "DestinationUnreachable" oder Code 3
                    if (!string.IsNullOrEmpty(icmpType))
                    {
                        var lower = icmpType.ToLowerInvariant();
                        if (lower.Contains("unreachable") || lower.Contains("destination unreachable") || lower.Contains("type=3"))
                        {
                            TcpMetrics.IcmpUnreachable++;
                        }
                    }
                }
            }

            // TCP-spezifische Fehlerindikatoren aus Details
            if (packet.Details != null)
            {
                foreach (var kv in packet.Details)
                {
                    var key = (kv.Key ?? string.Empty).ToLowerInvariant();
                    var val = (kv.Value ?? string.Empty).ToLowerInvariant();

                    if (key.Contains("retransmission") || val.Contains("retransmission"))
                        TcpMetrics.Retransmissions++;
                    else if ((key.Contains("fast") && key.Contains("retransmission")) || (val.Contains("fast") && val.Contains("retransmission")))
                        TcpMetrics.FastRetransmissions++;
                    else if ((key.Contains("duplicate") && key.Contains("ack")) || (val.Contains("duplicate") && val.Contains("ack")))
                        TcpMetrics.DuplicateAcks++;
                    else if (key.Contains("reset") || val.Contains("reset") || (val.Contains("rst") && key.Contains("tcp flags")))
                        TcpMetrics.Resets++;
                    else if (key.Contains("lost_segment") || val.Contains("lost segment") || key.Contains("tcp lost segment") || val.Contains("tcp lost segment"))
                        TcpMetrics.LostSegments++;
                    else if (key.Contains("out_of_order") || val.Contains("out of order") || key.Contains("tcp out-of-order") || val.Contains("tcp out of order"))
                        TcpMetrics.OutOfOrder++;
                    else if (key.Contains("zero_window") || val.Contains("zero window") || key.Contains("window size") && val.Contains("0"))
                        TcpMetrics.WindowSizeZero++;
                    else if (key.Contains("keep_alive") || val.Contains("keep alive") || key.Contains("keepalive") || val.Contains("keepalive"))
                        TcpMetrics.KeepAlive++;
                }
            }
        }

        /// <summary>
        /// Gibt die Instanznummer für eine IP zurück (falls vorhanden)
        /// </summary>
        public string? GetInstanceForIp(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
                return null;
            return IpToInstance.TryGetValue(ip, out var instance) ? instance : null;
        }

        /// <summary>
        /// Gibt eine Zusammenfassung der gesammelten Daten zurück
        /// </summary>
        public string GetSummary()
        {
            return $"BACnet-Datenbasis: {IpToInstance.Count} Instanzen, {IpToDeviceName.Count} Device-Namen, {IpToVendorId.Count} Vendor-IDs";
        }
    }
}
