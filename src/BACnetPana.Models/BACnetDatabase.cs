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

        // Menge aller Geräte (IP), die jemals ein BACnet-Paket gesendet haben
        public HashSet<string> AllDevices { get; } = new HashSet<string>();

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

            var sourceIp = string.IsNullOrWhiteSpace(packet.SourceIp) ? "Unbekannt" : packet.SourceIp;

            // Erkenne BACnet-Pakete mit der GLEICHEN Logik wie in AnalysisWindow!
            // 3-Teil-Filter: ApplicationProtocol ODER Destination-Port ODER Source-Port
            bool isApplicationProtocolBACnet = packet.ApplicationProtocol?.ToUpper() == "BACNET";
            bool isDestPortBACnet = packet.DestinationPort >= 47808 && packet.DestinationPort <= 47823;
            bool isSrcPortBACnet = packet.SourcePort >= 47808 && packet.SourcePort <= 47823;

            bool isBACnet = isApplicationProtocolBACnet || isDestPortBACnet || isSrcPortBACnet;

            if (!isBACnet)
                return;

            if (!string.IsNullOrWhiteSpace(sourceIp) && !string.Equals(sourceIp, "Unbekannt", StringComparison.OrdinalIgnoreCase))
            {
                AllDevices.Add(sourceIp);
            }

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
            string? instanceCandidate = null;
            string? deviceNameCandidate = null;
            string? vendorIdCandidate = null;
            bool isIAm = false;

            foreach (var detail in packet.Details)
            {
                var key = detail.Key?.ToLower() ?? string.Empty;
                var rawValue = detail.Value ?? string.Empty;
                var valueLower = rawValue.ToLower();

                // Prüfe ob es ein I-Am Paket ist (suche nach "i-am" oder "iam" im Value)
                if (!isIAm && (valueLower.Contains("i-am") || valueLower.Contains("iam")))
                {
                    isIAm = true;
                }

                // Priorität 1: bacapp.instance_number (bei I-Am Paketen)
                if (instanceCandidate == null && (key == "bacapp.instance_number" || key.Contains("instance_number")))
                {
                    if (!string.IsNullOrWhiteSpace(rawValue))
                    {
                        var extracted = ExtractInstanceNumber(rawValue);
                        if (!string.IsNullOrEmpty(extracted))
                            instanceCandidate = extracted;
                    }
                }

                // Priorität 2: "device,XXXXX" Pattern aus i-Am Service String
                if (instanceCandidate == null && valueLower.Contains("device,"))
                {
                    var parts = rawValue.Split(new[] { "device," }, StringSplitOptions.None);
                    if (parts.Length > 1)
                    {
                        var extracted = ExtractInstanceNumber(parts[1]);
                        if (!string.IsNullOrEmpty(extracted))
                            instanceCandidate = extracted;
                    }
                }

                // Priorität 3: objectidentifier, device_instance, etc.
                if (instanceCandidate == null)
                {
                    if (key.Contains("objectidentifier") ||
                        key.Contains("device_instance") ||
                        key.Contains("object_instance"))
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

            // Speichere Instanznummer (bei I-Am Paketen mit höchster Priorität)
            if (!string.IsNullOrEmpty(instanceCandidate))
            {
                if (isIAm)
                {
                    // Bei I-Am: Immer speichern/überschreiben
                    IpToInstance[sourceIp] = instanceCandidate;
                }
                else if (!IpToInstance.ContainsKey(sourceIp))
                {
                    // Bei anderen Paketen: Nur wenn noch nicht vorhanden
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
        /// Extrahiert I-Am Pakete aus einer PCAP-Datei mit tshark und befüllt IpToInstance
        /// Nutzt tshark Filter: bacnet.service == 0 (I-Am) oder "i-am" im Service-String
        /// </summary>
        public void ExtractIAmDevicesFromPcap(string pcapFilePath)
        {
            try
            {
                var tsharkPath = FindTShark();
                System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: tsharkPath = {tsharkPath ?? "NULL"}");

                if (string.IsNullOrWhiteSpace(tsharkPath))
                {
                    System.Diagnostics.Debug.WriteLine("ExtractIAmDevicesFromPcap: tshark nicht gefunden!");
                    return;
                }

                // Filter für I-Am (0) und I-Have (1) - nutze Info-Spalte zum Parsen von "device,XXXXX"
                // Felder: ip.src | bacapp.instance_number (I-Am) | _ws.col.Info (für I-Have parsing)
                var arguments = $"-r \"{pcapFilePath}\" -Y \"bacapp.unconfirmed_service == 0 || bacapp.unconfirmed_service == 1\" -T fields -e ip.src -e bacapp.instance_number -e _ws.col.Info";
                System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: Arguments = {arguments}");

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = tsharkPath,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(psi))
                {
                    if (process == null)
                    {
                        System.Diagnostics.Debug.WriteLine("ExtractIAmDevicesFromPcap: Process.Start() returned null");
                        return;
                    }

                    string output = process.StandardOutput.ReadToEnd();
                    string errorOutput = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: ExitCode = {process.ExitCode}");
                    System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: Output length = {output.Length}");
                    System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: StdErr = {errorOutput}");

                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: First 200 chars of output: {output.Substring(0, Math.Min(200, output.Length))}");
                    }

                    if (process.ExitCode != 0)
                    {
                        System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: tshark ExitCode != 0");
                        return;
                    }

                    // Parse Output: "IP\tInstance\tInfo\n..."
                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: Anzahl Zeilen = {lines.Length}");

                    int successCount = 0;
                    foreach (var line in lines)
                    {
                        var parts = line.Split(new[] { '\t' }, StringSplitOptions.None);
                        System.Diagnostics.Debug.WriteLine($"  Line: '{line}' -> Parts: {parts.Length}");

                        if (parts.Length >= 1)
                        {
                            string ip = parts[0].Trim();
                            string instance = "";

                            if (!string.IsNullOrWhiteSpace(ip))
                            {
                                AllDevices.Add(ip);
                            }

                            // Priorität 1: bacapp.instance_number (I-Am)
                            if (parts.Length >= 2 && !string.IsNullOrWhiteSpace(parts[1]))
                            {
                                instance = parts[1].Trim();
                            }

                            // Priorität 2: Parse "device,XXXXX" aus Info-Spalte (I-Have)
                            if (string.IsNullOrWhiteSpace(instance) && parts.Length >= 3)
                            {
                                string info = parts[2];
                                if (info.Contains("device,"))
                                {
                                    var deviceParts = info.Split(new[] { "device," }, StringSplitOptions.None);
                                    if (deviceParts.Length > 1)
                                    {
                                        // Extrahiere Ziffern nach "device,"
                                        instance = ExtractInstanceNumber(deviceParts[1]);
                                    }
                                }
                            }

                            System.Diagnostics.Debug.WriteLine($"    IP: '{ip}', Instance: '{instance}'");

                            if (!string.IsNullOrWhiteSpace(ip) && !string.IsNullOrWhiteSpace(instance))
                            {
                                IpToInstance[ip] = instance;
                                successCount++;
                                System.Diagnostics.Debug.WriteLine($"    ✓ Hinzugefügt");
                            }
                            else
                            {
                                System.Diagnostics.Debug.WriteLine($"    ✗ IP oder Instance leer");
                            }
                        }
                    }

                    System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: {successCount} Devices hinzugefügt. Total: {IpToInstance.Count}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap EXCEPTION: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap STACKTRACE: {ex.StackTrace}");
            }
        }

        /// <summary>
        /// Sucht tshark.exe in Standardpfaden
        /// </summary>
        private static string? FindTShark()
        {
            var possiblePaths = new[]
            {
                @"C:\Program Files\Wireshark\tshark.exe",
                @"C:\Program Files (x86)\Wireshark\tshark.exe",
                "tshark.exe"
            };

            foreach (var path in possiblePaths)
            {
                try
                {
                    if (System.IO.File.Exists(path))
                        return path;
                }
                catch { }
            }

            // Versuche aus PATH
            try
            {
                var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
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

            return null;
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
