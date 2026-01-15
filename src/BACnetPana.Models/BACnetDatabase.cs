namespace bacneTPana.Models
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

        // COV-Kombinationszähler: "Device-Instance-ObjectType,Instance" -> Häufigkeit
        // Beispiel: "40211-2,19" -> 100 (bedeutet: 100 COV-Pakete mit dieser exakten Kombination)
        public Dictionary<string, int> CovCombinationCounts { get; } = new Dictionary<string, int>();

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

            if (packet.Details == null || packet.Details.Count == 0)
            {
                return;
            }

            string? instanceCandidate = null;
            string? instanceSource = null;  // Woher kommt die Instance-Number?
            string? deviceNameCandidate = null;
            string? vendorIdCandidate = null;
            bool isIAm = false;
            bool isCov = false;  // Flag für COV-Pakete

            foreach (var detail in packet.Details)
            {
                var key = detail.Key?.ToLower() ?? string.Empty;
                var rawValue = detail.Value ?? string.Empty;
                var valueLower = rawValue.ToLower();

                // Prüfe ob es ein I-Am Paket ist (suche nach "i-am" oder "iam" im Value)
                if (!isIAm && (valueLower.Contains("i-am") || valueLower.Contains("iam")))
                {
                    isIAm = true;
                    System.Diagnostics.Debug.WriteLine($"[PACKET] IP={sourceIp}: Erkannt als I-Am Paket");
                }

                // Erkenne COV-Pakete (Confirmed Service == 1 oder Unconfirmed Service == 2)
                if (!isCov && (key.Contains("confirmed_service") || key.Contains("unconfirmed_service")))
                {
                    // Prüfe ob es eine COV ist
                    if (key.Contains("confirmed") && rawValue == "1")
                    {
                        isCov = true;
                        System.Diagnostics.Debug.WriteLine($"[PACKET] IP={sourceIp}: Erkannt als COV Paket (confirmed_service==1)");
                    }
                    else if (key.Contains("unconfirmed") && rawValue == "2")
                    {
                        isCov = true;
                        System.Diagnostics.Debug.WriteLine($"[PACKET] IP={sourceIp}: Erkannt als COV Paket (unconfirmed_service==2)");
                    }
                }

                // Priorität 1: bacapp.instance_number (bei I-Am Paketen)
                if (instanceCandidate == null && (key == "bacapp.instance_number" || key.Contains("instance_number")))
                {
                    if (!string.IsNullOrWhiteSpace(rawValue))
                    {
                        var extracted = ExtractInstanceNumber(rawValue);
                        if (!string.IsNullOrEmpty(extracted))
                        {
                            instanceCandidate = extracted;
                            instanceSource = $"Feld '{key}' (Wert: {rawValue})";
                            System.Diagnostics.Debug.WriteLine($"[PACKET] IP={sourceIp}: PRIORITÄT 1 - Instance aus '{key}'={rawValue} → {extracted}");
                        }
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
                        {
                            instanceCandidate = extracted;
                            instanceSource = $"Pattern 'device,XXXXX' aus Feld '{key}' (Wert: {rawValue})";
                            System.Diagnostics.Debug.WriteLine($"[PACKET] IP={sourceIp}: PRIORITÄT 2 - Instance aus 'device,'-Pattern in '{key}'={rawValue} → {extracted}");
                        }
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
                        {
                            instanceCandidate = parsed;
                            instanceSource = $"Feld '{key}' (Wert: {rawValue})";
                            System.Diagnostics.Debug.WriteLine($"[PACKET] IP={sourceIp}: PRIORITÄT 3 - Instance aus '{key}'={rawValue} → {parsed}");
                        }
                    }
                }

                // Suche nach Device-Namen
                if (deviceNameCandidate == null)
                {
                    if (key.Contains("object_name") || key.Contains("device_name") || key.Contains("name"))
                    {
                        if (!string.IsNullOrWhiteSpace(rawValue) && rawValue.Length > 1)
                        {
                            deviceNameCandidate = rawValue.Trim();
                            // Device-Namen werden NICHT geloggt, um die Ausgabe sauber zu halten
                        }
                    }
                }

                // Suche nach Vendor-ID
                if (vendorIdCandidate == null)
                {
                    if (key.Contains("vendor"))
                    {
                        if (!string.IsNullOrWhiteSpace(rawValue))
                        {
                            vendorIdCandidate = rawValue.Trim();
                            // Vendor-ID wird NICHT geloggt, um die Ausgabe sauber zu halten
                        }
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
                else if (isCov && !IpToInstance.ContainsKey(sourceIp))
                {
                    // Bei COV-Paketen: Nur wenn noch nicht vorhanden (geringere Priorität als I-Am)
                    IpToInstance[sourceIp] = instanceCandidate;
                }
                else if (!isIAm && !isCov && !IpToInstance.ContainsKey(sourceIp))
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
                //System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: tsharkPath = {tsharkPath ?? "NULL"}");

                if (string.IsNullOrWhiteSpace(tsharkPath))
                {
                    //System.Diagnostics.Debug.WriteLine("ExtractIAmDevicesFromPcap: tshark nicht gefunden!");
                    return;
                }

                // Filter für I-Am (0) und I-Have (1) - nutze Info-Spalte zum Parsen von "device,XXXXX"
                // Felder: ip.src | bacapp.instance_number (I-Am) | _ws.col.Info (für I-Have parsing)
                var arguments = $"-r \"{pcapFilePath}\" -Y \"bacapp.unconfirmed_service == 0 || bacapp.unconfirmed_service == 1\" -T fields -e ip.src -e bacapp.instance_number -e _ws.col.Info";
                //System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: Arguments = {arguments}");

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
                        //System.Diagnostics.Debug.WriteLine("ExtractIAmDevicesFromPcap: Process.Start() returned null");
                        return;
                    }

                    string output = process.StandardOutput.ReadToEnd();
                    string errorOutput = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    //System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: ExitCode = {process.ExitCode}");
                    //System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: Output length = {output.Length}");
                    //System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: StdErr = {errorOutput}");

                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        //System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: First 200 chars of output: {output.Substring(0, Math.Min(200, output.Length))}");
                    }

                    if (process.ExitCode != 0)
                    {
                        //System.Diagnostics.Debug.WriteLine($"ExtractIAmDevicesFromPcap: tshark ExitCode != 0");
                        return;
                    }

                    // Parse Output: "IP\tInstance\tInfo\n..."
                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    System.Diagnostics.Debug.WriteLine($"[STEP1] Gefunden: {lines.Length} Zeilen zur Analyse");

                    int successCount = 0;
                    foreach (var line in lines)
                    {
                        var parts = line.Split(new[] { '\t' }, StringSplitOptions.None);

                        if (parts.Length >= 1)
                        {
                            string ip = parts[0].Trim();
                            string instance = "";
                            string instanceSource = "";

                            if (!string.IsNullOrWhiteSpace(ip))
                            {
                                AllDevices.Add(ip);
                            }

                            // Priorität 1: bacapp.instance_number (I-Am)
                            if (parts.Length >= 2 && !string.IsNullOrWhiteSpace(parts[1]))
                            {
                                instance = parts[1].Trim();
                                instanceSource = $"Feld 'bacapp.instance_number' aus I-Am Paket (TShark)";
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
                                        instanceSource = $"Pattern 'device,XXXXX' aus I-Have Info-Spalte: '{info}'";
                                    }
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(ip) && !string.IsNullOrWhiteSpace(instance))
                            {
                                IpToInstance[ip] = instance;
                                successCount++;

                                // Debug: Zeige jedes gefundene Gerät mit Quelle
                                System.Diagnostics.Debug.WriteLine($"[STEP1:IAM] Gerät {successCount}: IP={ip}, Instance={instance}");
                                System.Diagnostics.Debug.WriteLine($"[STEP1:IAM]   └─ Quelle: {instanceSource}");
                            }
                        }
                    }

                    System.Diagnostics.Debug.WriteLine($"[STEP1] Gesamt (I-Am/I-Have): {successCount} BACnet-Geräte gefunden");
                }

                // Jetzt extrahiere zusätzliche Devices aus COV-Paketen (Change of Value)
                // COV: confirmed_service==1 || unconfirmed_service==2
                System.Diagnostics.Debug.WriteLine("[STEP1] Start: Extrahiere zusätzliche Devices aus COV-Paketen...");
                ExtractCovDevicesFromPcap(pcapFilePath, tsharkPath);
            }
            catch (Exception)
            {
                // Fehler werden absichtlich still behandelt, Geräte-Erkennung ist optional
            }
        }

        /// <summary>
        /// Extrahiert Device-IDs aus COV-Paketen (Change of Value)
        /// COV-Pakete enthalten Object-Type und Instance-Number, die auf die Quell-IP gemappt werden
        /// Filter: (bacapp.confirmed_service==1 || bacapp.unconfirmed_service==2)
        /// </summary>
        private void ExtractCovDevicesFromPcap(string pcapFilePath, string tsharkPath)
        {
            try
            {
                // COV: confirmed_service==1 oder unconfirmed_service==2
                // Extrahiere: IP | Object-Type | Instance-Number
                var arguments = $"-r \"{pcapFilePath}\" -Y \"bacapp.confirmed_service == 1 || bacapp.unconfirmed_service == 2\" -T fields -e ip.src -e bacapp.objectType -e bacapp.instance_number";

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
                        return;

                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
                        return;

                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    System.Diagnostics.Debug.WriteLine($"[STEP1] COV-Pakete: {lines.Length} Zeilen analysiert");

                    int covSuccessCount = 0;
                    foreach (var line in lines)
                    {
                        var parts = line.Split(new[] { '\t' }, StringSplitOptions.None);

                        if (parts.Length >= 3)
                        {
                            string ip = parts[0].Trim();
                            string objectTypesStr = parts[1].Trim();  // Kann mehrere Werte enthalten (z.B. "8,2")
                            string instancesStr = parts[2].Trim();    // Kann mehrere Werte enthalten (z.B. "40211,19")

                            // Splitte die durch Komma getrennten Werte
                            var objectTypes = objectTypesStr.Split(new[] { ',' }, System.StringSplitOptions.RemoveEmptyEntries);
                            var instances = instancesStr.Split(new[] { ',' }, System.StringSplitOptions.RemoveEmptyEntries);

                            // Suche nach Object-Type 8 (Device) und nehme die entsprechende Instance
                            string? deviceInstance = null;
                            for (int i = 0; i < objectTypes.Length && i < instances.Length; i++)
                            {
                                string objTypeStr = objectTypes[i].Trim();
                                string instStr = instances[i].Trim();

                                // Object-Type 8 = Device
                                if (objTypeStr == "8")
                                {
                                    deviceInstance = ExtractInstanceNumber(instStr);
                                    break;
                                }
                            }

                            // Fallback: Wenn kein Object-Type 8 gefunden, nimm den ersten Wert
                            if (string.IsNullOrWhiteSpace(deviceInstance) && instances.Length > 0)
                            {
                                deviceInstance = ExtractInstanceNumber(instances[0].Trim());
                            }

                            // Nur speichern wenn wir noch keine Instance für diese IP haben
                            if (!string.IsNullOrWhiteSpace(ip) && !string.IsNullOrWhiteSpace(deviceInstance) && !IpToInstance.ContainsKey(ip))
                            {
                                IpToInstance[ip] = deviceInstance;
                                covSuccessCount++;
                                System.Diagnostics.Debug.WriteLine($"[STEP1:COV] Gerät {covSuccessCount}: IP={ip}, Instance={deviceInstance}");
                                System.Diagnostics.Debug.WriteLine($"[STEP1:COV]   ├─ Object-Type: {objectTypesStr}");
                                System.Diagnostics.Debug.WriteLine($"[STEP1:COV]   ├─ Instance-Raw: {instancesStr}");
                                System.Diagnostics.Debug.WriteLine($"[STEP1:COV]   └─ Quelle: COV-Paket - Object-Type 8 (Device) mit Instance {deviceInstance}");
                            }
                            else if (IpToInstance.ContainsKey(ip))
                            {
                                // Gerät bereits vorhanden, übersprungen
                            }

                            // Sammle und zähle COV-Kombinationen für alle Devices
                            if (!string.IsNullOrWhiteSpace(deviceInstance))
                            {
                                // Zähle jede eindeutige Kombination: "Device-ObjectType,Instance"
                                for (int i = 0; i < objectTypes.Length && i < instances.Length; i++)
                                {
                                    string objType = objectTypes[i].Trim();
                                    string inst = ExtractInstanceNumber(instances[i].Trim());
                                    if (!string.IsNullOrWhiteSpace(inst))
                                    {
                                        // Erstelle eindeutige Kombinationschlüssel: "40211-2,19"
                                        string combinationKey = $"{deviceInstance}-{objType},{inst}";

                                        // Erhöhe Zähler für diese Kombination
                                        if (!CovCombinationCounts.ContainsKey(combinationKey))
                                            CovCombinationCounts[combinationKey] = 0;
                                        CovCombinationCounts[combinationKey]++;
                                    }
                                }
                            }
                        }
                    }

                    System.Diagnostics.Debug.WriteLine($"[STEP1] Zusätzlich aus COV: {covSuccessCount} Devices gefunden");
                }

                // Gebe Zusammenfassung aller COV-Kombinationen aus
                if (CovCombinationCounts.Count > 0)
                {
                    System.Diagnostics.Debug.WriteLine($"[STEP1:COV] Gefundene COV-Kombinationen (sortiert nach Häufigkeit):");

                    // Gruppiere nach Device-Instance
                    var groupedByDevice = CovCombinationCounts
                        .GroupBy(x => x.Key.Split('-')[0])
                        .OrderBy(g => int.TryParse(g.Key, out int val) ? val : int.MaxValue);

                    foreach (var deviceGroup in groupedByDevice)
                    {
                        string deviceInstance = deviceGroup.Key;
                        int totalForDevice = deviceGroup.Sum(x => x.Value);

                        System.Diagnostics.Debug.WriteLine($"[STEP1:COV] Device {deviceInstance} (Pakete: {totalForDevice}):");

                        // Sortiere Kombinationen nach Häufigkeit
                        var sortedCombinations = deviceGroup
                            .OrderByDescending(x => x.Value)
                            .ToList();

                        foreach (var combo in sortedCombinations)
                        {
                            // combo.Key = "40211-2,19", combo.Value = 100
                            string[] parts = combo.Key.Split('-');
                            string combination = parts.Length > 1 ? parts[1] : combo.Key;
                            System.Diagnostics.Debug.WriteLine($"[STEP1:COV]   ├─ {deviceInstance} - {combination}: {combo.Value} Pakete");
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Fehler werden absichtlich still behandelt
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

        /// <summary>
        /// Gibt die TOP 10 COV-Kombinationen sortiert nach Paketanzahl zurück
        /// Format: "40211-2,19" (100 Pakete), "40211-2,20" (85 Pakete), etc.
        /// Filtert Object-Type 8 (Device-Objekte) aus (z.B. "40211-8,40211")
        /// </summary>
        public List<(string CombinationKey, int PacketCount)> GetTop10CovCombinations()
        {
            // Sortiere alle Kombinationen nach Paketanzahl, filtere Object-Type 8 aus und nimm TOP 10
            return CovCombinationCounts
                .Where(x => !x.Key.Contains("-8,"))  // Filtere Object-Type 8 aus
                .OrderByDescending(x => x.Value)
                .Take(10)
                .Select(x => (x.Key, x.Value))
                .ToList();
        }

        /// <summary>
        /// Gibt die TOP 10 COV-Kombinationen für die UI zurück (Kompatibilität mit bestehendem Code)
        /// Filtert nach den übergebenen Paketen (Zeitfenster-Filterung)
        /// </summary>
        public List<dynamic> GetTop10CovPackets(List<NetworkPacket> filteredPackets, out int totalCovCount, double durationInSeconds = 0)
        {
            totalCovCount = 0;
            var result = new List<dynamic>();

            if (filteredPackets == null || filteredPackets.Count == 0)
            {
                System.Diagnostics.Debug.WriteLine("[COV-UI] Keine gefilterten Pakete vorhanden");
                return result;
            }

            // Filtere zuerst nach BACnet-Paketen (wie bei ReadProperties)
            var bacnetPackets = filteredPackets.Where(p =>
                (p.ApplicationProtocol?.ToUpper() == "BACNET") ||
                (p.DestinationPort >= 47808 && p.DestinationPort <= 47823) ||
                (p.SourcePort >= 47808 && p.SourcePort <= 47823)).ToList();

            if (bacnetPackets.Count == 0)
            {
                System.Diagnostics.Debug.WriteLine("[COV-UI] Keine BACnet-Pakete in gefilterten Paketen vorhanden");
                return result;
            }

            // Zähle COV-Kombinationen aus den gefilterten BACnet-Paketen
            var covCombinationCounts = new Dictionary<string, int>();

            foreach (var packet in bacnetPackets)
            {
                if (packet.Details == null || packet.Details.Count == 0)
                    continue;

                // Prüfe sowohl Confirmed als auch Unconfirmed Services auf COV
                int? serviceCode = null;
                bool isCov = false;

                // Prüfe Unconfirmed Service
                if (packet.Details.ContainsKey("BACnet Unconfirmed Service"))
                {
                    var unconfService = packet.Details["BACnet Unconfirmed Service"];
                    serviceCode = GetServiceCode(packet.Details, "BACnet Unconfirmed Service Code", "BACnet Unconfirmed Service");

                    // Unconfirmed COV Service Code: 2=UnconfirmedCOVNotification
                    isCov = serviceCode.HasValue && serviceCode.Value == 2;

                    if (!isCov && unconfService != null)
                    {
                        var svcLower = unconfService.ToLowerInvariant();
                        isCov = svcLower.Contains("cov");
                    }
                }

                // Prüfe Confirmed Service
                if (!isCov && packet.Details.ContainsKey("BACnet Confirmed Service"))
                {
                    var confService = packet.Details["BACnet Confirmed Service"];
                    serviceCode = GetServiceCode(packet.Details, "BACnet Confirmed Service Code", "BACnet Confirmed Service");

                    // Confirmed COV Service Codes: 1=ConfirmedCOVNotification, 5=SubscribeCOV, 28=SubscribeCOVProperty
                    isCov = serviceCode.HasValue && (serviceCode.Value == 1 || serviceCode.Value == 5 || serviceCode.Value == 28);

                    if (!isCov && confService != null)
                    {
                        var svcLower = confService.ToLowerInvariant();
                        isCov = svcLower.Contains("cov");
                    }
                }

                if (!isCov)
                    continue;

                // Extrahiere Object Types und Instance Numbers
                if (!packet.Details.TryGetValue("Object Type", out var objectTypesStr) ||
                    !packet.Details.TryGetValue("Instance Number", out var instancesStr))
                    continue;

                totalCovCount++; // Zähle alle COV-Pakete (nur wenn sie vollständige Details haben)

                // Extrahiere Device-Instance
                string? deviceInstance = null;
                if (packet.Details.TryGetValue("Initiating Device Identifier", out var deviceId))
                {
                    deviceInstance = ExtractInstanceNumber(deviceId);
                }

                // Splitte die durch Komma getrennten Werte (falls mehrere vorhanden)
                var objectTypes = objectTypesStr.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                var instances = instancesStr.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                if (objectTypes.Length == 0 || instances.Length == 0)
                    continue;

                // Wenn keine Device-Instance gefunden, versuche aus Object-Type 8 zu extrahieren
                if (string.IsNullOrWhiteSpace(deviceInstance))
                {
                    for (int i = 0; i < objectTypes.Length && i < instances.Length; i++)
                    {
                        if (objectTypes[i].Trim() == "8")
                        {
                            deviceInstance = ExtractInstanceNumber(instances[i].Trim());
                            break;
                        }
                    }
                }

                // Falls immer noch keine Device-Instance: Verwende SourceIP als Fallback
                if (string.IsNullOrWhiteSpace(deviceInstance))
                {
                    deviceInstance = packet.SourceIp ?? "unknown";
                }

                // Zähle jede eindeutige Kombination: "Device-ObjectType,Instance"
                for (int i = 0; i < objectTypes.Length && i < instances.Length; i++)
                {
                    string objType = objectTypes[i].Trim();
                    string inst = ExtractInstanceNumber(instances[i].Trim());

                    if (string.IsNullOrWhiteSpace(inst))
                        inst = instances[i].Trim(); // Fallback auf ungefilterten Wert

                    if (!string.IsNullOrWhiteSpace(inst))
                    {
                        // Erstelle eindeutigen Kombinationsschlüssel: "40211-2,19"
                        string combinationKey = $"{deviceInstance}-{objType},{inst}";

                        if (!covCombinationCounts.ContainsKey(combinationKey))
                            covCombinationCounts[combinationKey] = 0;
                        covCombinationCounts[combinationKey]++;
                    }
                }
            }

            System.Diagnostics.Debug.WriteLine($"[COV-UI] Gesamtanzahl COV-Pakete: {totalCovCount}, eindeutige Kombinationen: {covCombinationCounts.Count}");

            // TOP 10 nach Häufigkeit sortieren (ohne Device-Objekte)
            var covTopData = covCombinationCounts
                .Where(x => !x.Key.Contains("-8,"))  // Filtere Object-Type 8 (Device) aus
                .OrderByDescending(x => x.Value)
                .Take(10)
                .ToList();

            System.Diagnostics.Debug.WriteLine($"[COV-UI] TOP 10 COV-Kombinationen nach Filterung: {covTopData.Count}");

            foreach (var item in covTopData)
            {
                dynamic covPacket = new System.Dynamic.ExpandoObject();
                covPacket.DisplayFormat = item.Key;
                covPacket.Count = item.Value;

                // Berechne Rate pro Minute, wenn Zeitspanne gegeben ist
                if (durationInSeconds > 0)
                {
                    covPacket.RatePerMinute = (item.Value / durationInSeconds) * 60;
                }
                else
                {
                    covPacket.RatePerMinute = 0.0;
                }

                result.Add(covPacket);
            }

            return result;
        }

        private static int? GetServiceCode(Dictionary<string, string> details, string codeKey, string valueKey)
        {
            if (details.TryGetValue(codeKey, out var codeStr))
            {
                if (int.TryParse(codeStr, out var parsedCode))
                    return parsedCode;
            }

            if (details.TryGetValue(valueKey, out var valueStr))
            {
                if (TryParseServiceCode(valueStr, out var parsedCode))
                    return parsedCode;
            }

            return null;
        }

        private static bool TryParseServiceCode(string? serviceValue, out int serviceCode)
        {
            serviceCode = -1;
            if (string.IsNullOrWhiteSpace(serviceValue))
                return false;

            if (int.TryParse(serviceValue.Trim(), out serviceCode))
                return true;

            var digits = new string(serviceValue.Where(char.IsDigit).ToArray());
            if (!string.IsNullOrEmpty(digits) && int.TryParse(digits, out serviceCode))
                return true;

            return false;
        }

    }
}
