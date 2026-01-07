using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using BACnetPana.Models;

namespace BACnetPana.DataAccess
{
    /// <summary>
    /// Verwendet TShark (Wireshark CLI) zum Parsen von BACnet-Paketen aus PCAP-Dateien
    /// TShark muss installiert sein (normalerweise mit Wireshark)
    /// </summary>
    public class TSharkBACnetParser : IPcapParser
    {
        private readonly string _tsharkPath;
        public event EventHandler<string>? ProgressChanged;

        // BACnet-Datenbasis wird während des Parsens aufgebaut
        public BACnetDatabase BACnetDb { get; private set; } = new BACnetDatabase();

        /// <summary>
        /// Erstellt einen neuen TShark-Parser
        /// </summary>
        /// <param name="tsharkPath">Pfad zu tshark.exe (null = automatische Suche)</param>
        public TSharkBACnetParser(string? tsharkPath = null)
        {
            _tsharkPath = tsharkPath ?? FindTShark();
        }

        /// <summary>
        /// Sucht TShark in den Standard-Installationspfaden
        /// </summary>
        private static string FindTShark()
        {
            var possiblePaths = new[]
            {
                @"C:\Program Files\Wireshark\tshark.exe",
                @"C:\Program Files (x86)\Wireshark\tshark.exe",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wireshark", "tshark.exe"),
                "tshark.exe" // Im PATH
            };

            foreach (var path in possiblePaths)
            {
                if (File.Exists(path))
                    return path;
            }

            // Versuche tshark aus PATH
            try
            {
                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = "tshark",
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                });

                if (process != null)
                {
                    process.WaitForExit();
                    if (process.ExitCode == 0)
                        return "tshark";
                }
            }
            catch { }

            throw new FileNotFoundException(
                "TShark wurde nicht gefunden. Bitte installieren Sie Wireshark oder geben Sie den Pfad zu tshark.exe an.");
        }

        /// <summary>
        /// Prüft ob TShark verfügbar ist
        /// </summary>
        public bool IsTSharkAvailable()
        {
            try
            {
                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = _tsharkPath,
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                });

                if (process != null)
                {
                    process.WaitForExit();
                    return process.ExitCode == 0;
                }
            }
            catch { }

            return false;
        }

        /// <summary>
        /// Liest PCAP-Datei und parst BACnet-Pakete mit TShark
        /// </summary>
        public async Task<List<NetworkPacket>> ReadPcapFileAsync(string filePath)
        {
            return await Task.Run(() => ReadPcapFile(filePath));
        }

        /// <summary>
        /// Liest PCAP-Datei und parst BACnet-Pakete mit TShark
        /// </summary>
        public List<NetworkPacket> ReadPcapFile(string filePath)
        {
            var packets = new List<NetworkPacket>();
            BACnetDb = new BACnetDatabase(); // Reset bei jedem neuen File

            try
            {
                ProgressChanged?.Invoke(this, "Starte TShark...");

                // TShark-Aufruf mit JSON-Export
                // -r: Lese PCAP-Datei
                // -T json: JSON-Ausgabeformat
                // -e: Felder extrahieren (nur benötigte Felder für Performance)
                var arguments = $"-r \"{filePath}\" -T json " +
                    "-e frame.number " +
                    "-e frame.time_epoch " +
                    "-e frame.len " +
                    "-e eth.src " +
                    "-e eth.dst " +
                    "-e eth.type " +
                    "-e ip.src " +
                    "-e ip.dst " +
                    "-e ip.proto " +
                    "-e ip.ttl " +
                    "-e udp.srcport " +
                    "-e udp.dstport " +
                    "-e tcp.srcport " +
                    "-e tcp.dstport " +
                    "-e bacnet " +
                    "-e bacapp.type " +
                    "-e bacapp.confirmed_service " +
                    "-e bacapp.unconfirmed_service " +
                    "-e bacapp.invoke_id " +
                    "-e bacapp.objectType " +
                    "-e bacapp.instance_number " +
                    "-e bacapp.property_identifier " +
                    "-e bacapp.vendor_identifier " +
                    "-e bacapp.object_name";

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = _tsharkPath,
                        Arguments = arguments,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        StandardOutputEncoding = System.Text.Encoding.UTF8
                    }
                };

                process.Start();

                // Lese JSON-Output
                string jsonOutput = process.StandardOutput.ReadToEnd();
                string errorOutput = process.StandardError.ReadToEnd();

                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new Exception($"TShark Fehler: {errorOutput}");
                }

                ProgressChanged?.Invoke(this, "Parse JSON-Daten...");

                // Parse JSON
                packets = ParseTSharkJson(jsonOutput);

                ProgressChanged?.Invoke(this, $"Fertig: {packets.Count} Pakete gelesen");
                ProgressChanged?.Invoke(this, BACnetDb.GetSummary());
            }
            catch (Exception ex)
            {
                ProgressChanged?.Invoke(this, $"Fehler: {ex.Message}");
                throw;
            }

            return packets;
        }

        /// <summary>
        /// Parst TShark JSON-Output und erstellt NetworkPacket-Objekte
        /// </summary>
        private List<NetworkPacket> ParseTSharkJson(string jsonOutput)
        {
            var packets = new List<NetworkPacket>();

            try
            {
                using var document = JsonDocument.Parse(jsonOutput);
                var root = document.RootElement;

                int packetCount = 0;

                foreach (var item in root.EnumerateArray())
                {
                    packetCount++;

                    try
                    {
                        var packet = ParsePacketFromJson(item, packetCount);
                        packets.Add(packet);

                        // Verarbeite BACnet-Informationen
                        BACnetDb.ProcessPacket(packet);

                        if (packetCount % 5000 == 0)
                        {
                            ProgressChanged?.Invoke(this, $"Verarbeitet: {packetCount} Pakete");
                        }
                    }
                    catch (Exception ex)
                    {
                        ProgressChanged?.Invoke(this, $"Warnung bei Paket {packetCount}: {ex.Message}");
                    }
                }
            }
            catch (JsonException ex)
            {
                throw new Exception($"Fehler beim Parsen der JSON-Daten: {ex.Message}", ex);
            }

            return packets;
        }

        /// <summary>
        /// Erstellt ein NetworkPacket aus TShark JSON-Element
        /// </summary>
        private NetworkPacket ParsePacketFromJson(JsonElement item, int packetCount)
        {
            var layers = item.GetProperty("_source").GetProperty("layers");

            var packet = new NetworkPacket
            {
                PacketNumber = GetIntField(layers, "frame.number", packetCount),
                PacketLength = GetLongField(layers, "frame.len", 0)
            };

            // Timestamp (Unix-Epoch in Sekunden)
            if (TryGetStringField(layers, "frame.time_epoch", out string? epochStr))
            {
                if (double.TryParse(epochStr, System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out double epoch))
                {
                    packet.Timestamp = DateTimeOffset.FromUnixTimeSeconds((long)epoch)
                        .AddSeconds(epoch - (long)epoch) // Millisekunden
                        .LocalDateTime;
                }
            }

            // Layer 2 (Ethernet)
            packet.SourceMac = GetStringField(layers, "eth.src");
            packet.DestinationMac = GetStringField(layers, "eth.dst");
            packet.EthernetType = GetStringField(layers, "eth.type");

            // Layer 3 (IP)
            packet.SourceIp = GetStringField(layers, "ip.src");
            packet.DestinationIp = GetStringField(layers, "ip.dst");
            packet.Protocol = GetProtocolName(GetStringField(layers, "ip.proto"));
            packet.Ttl = GetIntField(layers, "ip.ttl", 0);

            // Layer 4 (Transport) - UDP oder TCP
            int srcPort = GetIntField(layers, "udp.srcport", 0);
            int dstPort = GetIntField(layers, "udp.dstport", 0);

            if (srcPort == 0 && dstPort == 0)
            {
                srcPort = GetIntField(layers, "tcp.srcport", 0);
                dstPort = GetIntField(layers, "tcp.dstport", 0);
            }

            packet.SourcePort = srcPort;
            packet.DestinationPort = dstPort;

            // BACnet Erkennung und Details
            ParseBACnetDetails(layers, packet);

            // Summary erstellen
            packet.Summary = CreateSummary(packet);

            return packet;
        }

        /// <summary>
        /// Parst BACnet-spezifische Felder aus TShark
        /// </summary>
        private void ParseBACnetDetails(JsonElement layers, NetworkPacket packet)
        {
            // Prüfe ob BACnet-Layer vorhanden ist
            if (!layers.TryGetProperty("bacnet", out _) &&
                !layers.TryGetProperty("bacapp", out _))
            {
                return;
            }

            packet.ApplicationProtocol = "BACnet";

            // Extrahiere BACnet-Details
            string serviceType = GetStringField(layers, "bacapp.type");
            // Service kann confirmed oder unconfirmed sein
            string confirmedService = GetStringField(layers, "bacapp.confirmed_service");
            string unconfirmedService = GetStringField(layers, "bacapp.unconfirmed_service");
            string service = !string.IsNullOrEmpty(confirmedService) ? confirmedService : unconfirmedService;

            string invokeId = GetStringField(layers, "bacapp.invoke_id");
            string objectType = GetStringField(layers, "bacapp.objectType");
            string instanceNumber = GetStringField(layers, "bacapp.instance_number");
            string propertyId = GetStringField(layers, "bacapp.property_identifier");
            string vendorId = GetStringField(layers, "bacapp.vendor_identifier");
            string objectName = GetStringField(layers, "bacapp.object_name");

            // Füge Details hinzu
            if (!string.IsNullOrEmpty(serviceType))
                packet.Details["BACnet Type"] = serviceType;

            if (!string.IsNullOrEmpty(service))
                packet.Details["BACnet Service"] = service;

            if (!string.IsNullOrEmpty(invokeId))
                packet.Details["Invoke ID"] = invokeId;

            if (!string.IsNullOrEmpty(objectType))
                packet.Details["Object Type"] = objectType;

            if (!string.IsNullOrEmpty(instanceNumber))
                packet.Details["Instance Number"] = instanceNumber;

            if (!string.IsNullOrEmpty(propertyId))
                packet.Details["Property"] = propertyId;

            if (!string.IsNullOrEmpty(vendorId))
                packet.Details["Vendor ID"] = vendorId;

            if (!string.IsNullOrEmpty(objectName))
                packet.Details["Object Name"] = objectName;
        }

        /// <summary>
        /// Erstellt eine Zusammenfassung für das Paket
        /// </summary>
        private string CreateSummary(NetworkPacket packet)
        {
            if (packet.ApplicationProtocol == "BACnet" && packet.Details.Count > 0)
            {
                var service = packet.Details.ContainsKey("BACnet Service")
                    ? packet.Details["BACnet Service"]
                    : "Unknown";

                var parts = new List<string> { service };

                if (packet.Details.ContainsKey("Object Type"))
                    parts.Add(packet.Details["Object Type"]);

                if (packet.Details.ContainsKey("Instance Number"))
                    parts.Add($"#{packet.Details["Instance Number"]}");

                if (packet.Details.ContainsKey("Property"))
                    parts.Add(packet.Details["Property"]);

                return string.Join(" ", parts);
            }

            return $"{packet.Protocol} {packet.SourceIp}:{packet.SourcePort} → {packet.DestinationIp}:{packet.DestinationPort}";
        }

        // Hilfs-Methoden zum sicheren Lesen von JSON-Feldern
        private string GetStringField(JsonElement layers, string fieldName)
        {
            TryGetStringField(layers, fieldName, out string? value);
            return value ?? string.Empty;
        }

        private bool TryGetStringField(JsonElement layers, string fieldName, out string? value)
        {
            value = null;
            if (layers.TryGetProperty(fieldName, out JsonElement element))
            {
                if (element.ValueKind == JsonValueKind.Array && element.GetArrayLength() > 0)
                {
                    value = element[0].GetString();
                    return !string.IsNullOrEmpty(value);
                }
                else if (element.ValueKind == JsonValueKind.String)
                {
                    value = element.GetString();
                    return !string.IsNullOrEmpty(value);
                }
            }
            return false;
        }

        private int GetIntField(JsonElement layers, string fieldName, int defaultValue)
        {
            var strValue = GetStringField(layers, fieldName);
            return int.TryParse(strValue, out int value) ? value : defaultValue;
        }

        private long GetLongField(JsonElement layers, string fieldName, long defaultValue)
        {
            var strValue = GetStringField(layers, fieldName);
            return long.TryParse(strValue, out long value) ? value : defaultValue;
        }

        private string GetProtocolName(string protocolNumber)
        {
            return protocolNumber switch
            {
                "6" => "TCP",
                "17" => "UDP",
                "1" => "ICMP",
                "2" => "IGMP",
                _ => protocolNumber
            };
        }
    }
}
