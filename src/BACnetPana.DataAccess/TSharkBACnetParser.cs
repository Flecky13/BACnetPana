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
        public async Task<List<NetworkPacket>> ReadPcapFileAsync(string filePath, System.Threading.CancellationToken cancellationToken = default)
        {
            return await Task.Run(() => ReadPcapFile(filePath, cancellationToken), cancellationToken);
        }

        /// <summary>
        /// Liest PCAP-Datei und parst BACnet-Pakete mit TShark
        /// </summary>
        public List<NetworkPacket> ReadPcapFile(string filePath, System.Threading.CancellationToken cancellationToken = default)
        {
            var packets = new List<NetworkPacket>();
            BACnetDb = new BACnetDatabase(); // Reset bei jedem neuen File

            try
            {
                ProgressChanged?.Invoke(this, "Starte TShark...");

                // TShark-Aufruf mit JSON-Export
                // -r: Lese PCAP-Datei
                // -Y: Display-Filter NUR für BACnet-Pakete (reduziert Datenmenge massiv!)
                // -T json: JSON-Ausgabeformat
                // -e: Felder extrahieren (nur benötigte Felder für Performance)
                var arguments = $"-r \"{filePath}\" -Y \"bacnet or bacapp\" -T json " +
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
                    // TCP Analyse Felder
                    "-e tcp.seq " +
                    "-e tcp.ack " +
                    "-e tcp.flags.reset " +
                    "-e tcp.analysis.retransmission " +
                    "-e tcp.analysis.fast_retransmission " +
                    "-e tcp.analysis.duplicate_ack " +
                    "-e tcp.analysis.lost_segment " +
                    // ICMP Felder
                    "-e icmp.type " +
                    "-e icmp.code " +
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

                ProgressChanged?.Invoke(this, "Parse JSON-Daten (Stream)...");

                // Parse JSON direkt aus dem Stream für bessere Memory-Effizienz
                // Bei sehr großen Dateien kann das immer noch viel Speicher benötigen
                try
                {
                    packets = ParseTSharkJsonStreamOptimized(process.StandardOutput, cancellationToken);
                }
                catch (OutOfMemoryException)
                {
                    // Fallback: Versuche mit ReadToEnd (alte Methode) wenn Stream-Parsing fehlschlägt
                    ProgressChanged?.Invoke(this, "Speicherproblem - versuche alternative Methode...");
                    throw; // Re-throw für jetzt, keine alternative Methode
                }

                // Lese Fehlerausgabe
                string errorOutput = process.StandardError.ReadToEnd();

                process.WaitForExit();

                if (process.ExitCode != 0 && packets.Count == 0)
                {
                    throw new Exception($"TShark Fehler: {errorOutput}");
                }

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
        /// Parst TShark JSON-Output mit optimiertem Streaming für sehr große Dateien
        /// </summary>
        private List<NetworkPacket> ParseTSharkJsonStreamOptimized(System.IO.StreamReader reader, System.Threading.CancellationToken cancellationToken)
        {
            var packets = new List<NetworkPacket>();
            int packetCount = 0;
            string? tempFilePath = null;

            try
            {
                // Strategie für sehr große Dateien: Verwende temporäre Datei statt MemoryStream
                // MemoryStream hat eine Größenbeschränkung, Dateien nicht

                ProgressChanged?.Invoke(this, "Starte JSON-Stream-Parsing...");

                // Erstelle temporäre Datei
                tempFilePath = Path.Combine(Path.GetTempPath(), $"tshark_output_{Guid.NewGuid()}.json");

                // Lese in Chunks und schreibe in temporäre Datei
                const int bufferSize = 81920; // 80KB Chunks
                var buffer = new char[bufferSize];
                long totalCharsRead = 0;

                using (var fileStream = new FileStream(tempFilePath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize))
                using (var writer = new StreamWriter(fileStream, System.Text.Encoding.UTF8))
                {
                    while (true)
                    {
                        int charsRead = reader.Read(buffer, 0, bufferSize);
                        if (charsRead == 0) break;

                        writer.Write(buffer, 0, charsRead);
                        totalCharsRead += charsRead;

                        if (totalCharsRead % (bufferSize * 10) == 0) // Alle ~800KB
                        {
                            long megabytes = (totalCharsRead * 2) / 1024 / 1024; // Ungefähr 2 Bytes pro Char
                            ProgressChanged?.Invoke(this, $"Gelesen: ~{megabytes} MB");
                            cancellationToken.ThrowIfCancellationRequested();
                        }
                    }
                }

                long fileSizeMB = new FileInfo(tempFilePath).Length / 1024 / 1024;
                ProgressChanged?.Invoke(this, $"JSON gespeichert ({fileSizeMB} MB), parse Pakete...");

                // Jetzt parse das JSON aus der temporären Datei
                using (var fileStream = new FileStream(tempFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var document = JsonDocument.Parse(fileStream, new JsonDocumentOptions
                {
                    AllowTrailingCommas = true,
                    MaxDepth = 128
                }))
                {
                    var root = document.RootElement;

                    if (root.ValueKind != JsonValueKind.Array)
                    {
                        throw new Exception("TShark JSON ist kein Array");
                    }

                    foreach (var item in root.EnumerateArray())
                    {
                        // Prüfe Abbruch alle 5000 Pakete
                        if (packetCount % 5000 == 0)
                            cancellationToken.ThrowIfCancellationRequested();

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
            }
            catch (JsonException ex)
            {
                throw new Exception($"Fehler beim Parsen der JSON-Daten bei Paket {packetCount}: {ex.Message}", ex);
            }
            catch (OutOfMemoryException ex)
            {
                throw new Exception($"Nicht genug Speicher für diese PCAP-Datei. " +
                    $"Bisher gelesen: {packets.Count} Pakete. " +
                    $"Bitte verwenden Sie eine kleinere Datei oder teilen Sie die PCAP auf.", ex);
            }
            finally
            {
                // Lösche temporäre Datei
                if (tempFilePath != null && File.Exists(tempFilePath))
                {
                    try
                    {
                        File.Delete(tempFilePath);
                    }
                    catch
                    {
                        // Ignoriere Fehler beim Löschen
                    }
                }
            }

            return packets;
        }

        /// <summary>
        /// Parst TShark JSON-Output direkt aus dem Stream (memory-effizient für große Dateien)
        /// </summary>
        private List<NetworkPacket> ParseTSharkJsonStream(System.IO.StreamReader reader, System.Threading.CancellationToken cancellationToken)
        {
            var packets = new List<NetworkPacket>();
            int packetCount = 0;

            try
            {
                // Für große Dateien: Lese komplettes JSON in Chunks
                ProgressChanged?.Invoke(this, "Lade JSON-Daten...");

                string jsonContent = reader.ReadToEnd();

                ProgressChanged?.Invoke(this, "Parse JSON-Daten...");

                // Verwende den normalen JSON-Parser mit Streaming
                using var document = JsonDocument.Parse(jsonContent, new JsonDocumentOptions
                {
                    AllowTrailingCommas = true,
                    MaxDepth = 128
                });

                var root = document.RootElement;

                if (root.ValueKind != JsonValueKind.Array)
                {
                    throw new Exception("TShark JSON ist kein Array");
                }

                foreach (var item in root.EnumerateArray())
                {
                    // Prüfe Abbruch alle 5000 Pakete
                    if (packetCount % 5000 == 0)
                        cancellationToken.ThrowIfCancellationRequested();

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
                throw new Exception($"Fehler beim Parsen der JSON-Daten bei Paket {packetCount}: {ex.Message}", ex);
            }
            catch (OutOfMemoryException ex)
            {
                throw new Exception($"Speicher voll bei Paket {packetCount}. Bisher gelesen: {packets.Count} Pakete. " +
                    "Die PCAP-Datei ist zu groß. Versuchen Sie eine kleinere Datei oder teilen Sie die PCAP-Datei.", ex);
            }

            return packets;
        }

        /// <summary>
        /// Parst TShark JSON-Output und erstellt NetworkPacket-Objekte (Legacy-Methode)
        /// </summary>
        private List<NetworkPacket> ParseTSharkJson(string jsonOutput, System.Threading.CancellationToken cancellationToken)
        {
            var packets = new List<NetworkPacket>();

            try
            {
                using var document = JsonDocument.Parse(jsonOutput);
                var root = document.RootElement;

                int packetCount = 0;

                foreach (var item in root.EnumerateArray())
                {
                    // Prüfe Abbruch alle 5000 Pakete
                    if (packetCount % 5000 == 0)
                        cancellationToken.ThrowIfCancellationRequested();

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

            // TCP Sequenz & ACK
            var tcpSeq = GetStringField(layers, "tcp.seq");
            if (!string.IsNullOrEmpty(tcpSeq))
                packet.Details["Sequence"] = tcpSeq;
            var tcpAck = GetStringField(layers, "tcp.ack");
            if (!string.IsNullOrEmpty(tcpAck))
                packet.Details["Acknowledgment"] = tcpAck;

            // TCP Reset Flag
            var tcpReset = GetStringField(layers, "tcp.flags.reset");
            if (!string.IsNullOrEmpty(tcpReset))
            {
                if (tcpReset == "1" || tcpReset.Equals("true", StringComparison.OrdinalIgnoreCase))
                    packet.Details["TCP Reset"] = "true";
            }

            // TCP Analyse: Retransmission, Fast Retransmission, Duplicate ACK
            if (TryGetStringField(layers, "tcp.analysis.retransmission", out string? retr))
            {
                packet.Details["TCP Retransmission"] = string.IsNullOrEmpty(retr) ? "true" : retr;
            }
            if (TryGetStringField(layers, "tcp.analysis.fast_retransmission", out string? fretr))
            {
                packet.Details["TCP Fast Retransmission"] = string.IsNullOrEmpty(fretr) ? "true" : fretr;
            }
            if (TryGetStringField(layers, "tcp.analysis.duplicate_ack", out string? dack))
            {
                packet.Details["TCP Duplicate ACK"] = string.IsNullOrEmpty(dack) ? "true" : dack;
            }
            if (TryGetStringField(layers, "tcp.analysis.lost_segment", out string? lost))
            {
                packet.Details["TCP Lost Segment"] = string.IsNullOrEmpty(lost) ? "true" : lost;
            }

            // ICMP Typ/Code
            var icmpType = GetStringField(layers, "icmp.type");
            var icmpCode = GetStringField(layers, "icmp.code");
            if (!string.IsNullOrEmpty(icmpType))
                packet.Details["ICMP Type"] = icmpType;
            if (!string.IsNullOrEmpty(icmpCode))
                packet.Details["ICMP Code"] = icmpCode;

            // BACnet Erkennung und Details
            ParseBACnetDetails(layers, packet);

            // Summary erstellen
            packet.Summary = CreateSummary(packet);

            // TCP/ICMP Felder in Datenbankmetrik aufnehmen
            BACnetDb.ProcessTcpFields(packet);

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

            // Speichere Services getrennt nach confirmed/unconfirmed und als Fallback kombiniert
            if (!string.IsNullOrEmpty(confirmedService))
            {
                packet.Details["BACnet Confirmed Service"] = confirmedService;
                if (TryParseServiceCode(confirmedService, out var confirmedCode))
                {
                    packet.Details["BACnet Confirmed Service Code"] = confirmedCode.ToString();
                }
            }

            if (!string.IsNullOrEmpty(unconfirmedService))
            {
                packet.Details["BACnet Unconfirmed Service"] = unconfirmedService;
                if (TryParseServiceCode(unconfirmedService, out var unconfirmedCode))
                {
                    packet.Details["BACnet Unconfirmed Service Code"] = unconfirmedCode.ToString();
                }
            }

            if (!string.IsNullOrEmpty(service))
            {
                packet.Details["BACnet Service"] = service;
                if (TryParseServiceCode(service, out var serviceCode))
                {
                    packet.Details["BACnet Service Code"] = serviceCode.ToString();
                }
            }

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

        private bool TryParseServiceCode(string? serviceValue, out int serviceCode)
        {
            serviceCode = -1;
            if (string.IsNullOrWhiteSpace(serviceValue))
                return false;

            // Direkte Zahl versuchen
            if (int.TryParse(serviceValue.Trim(), out serviceCode))
                return true;

            // Extrahiere erste Ziffernfolge (z.B. "readProperty(12)" -> 12)
            var digits = new string(serviceValue.Where(char.IsDigit).ToArray());
            if (!string.IsNullOrEmpty(digits) && int.TryParse(digits, out serviceCode))
                return true;

            return false;
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
