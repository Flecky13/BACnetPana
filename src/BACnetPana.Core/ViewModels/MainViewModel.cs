using bacneTPana.DataAccess;
using bacneTPana.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;

namespace bacneTPana.Core.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        private readonly PcapFileReader _sharpPcapReader;
        private TSharkBACnetParser? _tsharkParser;
        private bool _tsharkAvailable = false;
        private readonly StatisticsCalculator _statsCalculator;
        private SynchronizationContext _synchronizationContext;

        [ObservableProperty]
        private ObservableCollection<NetworkPacket> packets;

        [ObservableProperty]
        private ObservableCollection<string> logMessages;

        [ObservableProperty]
        private NetworkPacket? selectedPacket;

        [ObservableProperty]
        private PacketStatistics packetStatistics = new();

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string loadingMessage = string.Empty;

        [ObservableProperty]
        private int loadedPacketCount;

        [ObservableProperty]
        private int loadProgress;

        [ObservableProperty]
        private int phase1Progress;

        [ObservableProperty]
        private int phase2Progress;

        [ObservableProperty]
        private string phase1Message = "Phase 1: Bereit";

        [ObservableProperty]
        private string phase2Message = "Phase 2: Warte auf Phase 1";

        [ObservableProperty]
        private BACnetDatabase? bacnetDatabase;

        [ObservableProperty]
        private bool isPhase1Complete;

        [ObservableProperty]
        private bool isPhase2Complete;

        [ObservableProperty]
        private bool isAnalysisReady;

        [ObservableProperty]
        private string? currentAnalysisFile;

        private string? _lastLogBase;
        private DateTime _lastLogTime;
        private int _lastLogRepeatCount;

        public MainViewModel()
        {
            // Immer SharpPcap für das generelle Parsing verwenden
            _sharpPcapReader = new PcapFileReader();
            _statsCalculator = new StatisticsCalculator();
            _synchronizationContext = SynchronizationContext.Current ?? new SynchronizationContext();

            Packets = new ObservableCollection<NetworkPacket>();
            LogMessages = new ObservableCollection<string>();

            AddLog("BACnetAna initialisiert");
            AddLog("───────────────────────────────────────────────────");

            // Prüfe TShark-Verfügbarkeit für BACnet-Details
            try
            {
                _tsharkParser = new TSharkBACnetParser();
                _tsharkParser.ProgressChanged += OnPhase2ProgressChanged;
                if (_tsharkParser.IsTSharkAvailable())
                {
                    _tsharkAvailable = true;
                    AddLog("✅ TShark verfügbar");
                    AddLog("    → BACnet-Pakete werden mit TShark im Detail analysiert");
                }
                else
                {
                    AddLog("⚠️  TShark nicht gefunden");
                    AddLog("    → BACnet-Pakete werden mit SharpPcap analysiert (grundlegend)");
                }
            }
            catch (Exception)
            {
                AddLog("⚠️  TShark nicht verfügbar");
                AddLog("    → BACnet-Pakete werden mit SharpPcap analysiert (grundlegend)");
            }

            AddLog("✅ SharpPcap-Parser für alle Protokolle");
            AddLog("───────────────────────────────────────────────────");

            _sharpPcapReader.ProgressChanged += OnProgressChanged;
        }

        /// <summary>
        /// Öffnet eine PCAP-Datei mit Progress-Callback für separates Fenster und Abbruch-Unterstützung
        /// </summary>
        public async Task<(List<NetworkPacket> packets, PacketStatistics statistics)?> OpenPcapFileWithProgress(string filePath, Action<string, string, int> progressCallback, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(filePath))
                return null;

            try
            {
                IsLoading = true;
                IsPhase1Complete = false;
                IsPhase2Complete = false;
                IsAnalysisReady = false;
                LoadedPacketCount = 0;
                CurrentAnalysisFile = filePath;

                AddLog($"Öffne Datei: {filePath}");

                // Phase 1: Mit SharpPcap alle Pakete einlesen
                progressCallback("Phase 1/2", "Lese Pakete mit SharpPcap...", 0);
                AddLog("Phase 1: Lese alle Pakete mit SharpPcap...");

                // Temporärer ProgressChanged-Handler für Phase 1
                int totalPhases = _tsharkAvailable ? 2 : 1;
                EventHandler<string>? phase1Handler = (s, msg) =>
                {
                    if (msg.Contains("(") && msg.Contains("%"))
                    {
                        try
                        {
                            int percentStart = msg.LastIndexOf('(');
                            int percentEnd = msg.LastIndexOf('%');
                            if (percentStart >= 0 && percentEnd > percentStart)
                            {
                                string percentStr = msg.Substring(percentStart + 1, percentEnd - percentStart - 1);
                                if (int.TryParse(percentStr, out int percent))
                                {
                                    progressCallback($"Phase 1/{totalPhases}", msg, percent);
                                }
                            }
                        }
                        catch { }
                    }
                };

                _sharpPcapReader.ProgressChanged += phase1Handler;

                var packetList = await _sharpPcapReader.ReadPcapFileAsync(filePath, cancellationToken);

                _sharpPcapReader.ProgressChanged -= phase1Handler;

                cancellationToken.ThrowIfCancellationRequested();

                // Filtere reassemblierte Pakete (Fragmente) aus
                var completePackets = packetList.Where(p => !p.IsReassembled).ToList();
                var reassembledCount = packetList.Count - completePackets.Count;

                // Speichere BACnet-Datenbasis von SharpPcap
                BacnetDatabase = _sharpPcapReader.BACnetDb;

                IsPhase1Complete = true;
                progressCallback($"Phase 1/{totalPhases}", $"✅ SharpPcap: {completePackets.Count} Pakete geladen", 100);

                AddLog($"✅ SharpPcap: {completePackets.Count} komplette Pakete geladen");
                if (reassembledCount > 0)
                {
                    AddLog($"   Gefiltert: {reassembledCount} fragmentierte Pakete");
                }

                // Berechne Statistiken
                var statistics = _statsCalculator.CalculateStatistics(packetList);

                // Phase 2: Falls TShark verfügbar, BACnet-Details anreichern
                if (_tsharkAvailable && _tsharkParser != null)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    progressCallback("Phase 2/2", "Start: Extrahiere Device Instanzen", 0);
                    AddLog("Phase 2: Extrahiere Device Instanzen...");

                    // Timer für STEP1 Animation
                    System.Timers.Timer? animationTimer = null;
                    int animationFrame = 0;
                    string[] animationChars = { "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█" }; // Balken-Animation

                    EventHandler<string>? phase2Handler = (s, msg) =>
                    {
                        try
                        {
                            // Animation für STEP 1
                            if (msg.StartsWith("[ANIM]"))
                            {
                                var baseText = msg.Substring(6); // Entferne "[ANIM]"

                                // Starte Animation wenn nicht schon läuft
                                if (animationTimer == null)
                                {
                                    animationFrame = 0;
                                    animationTimer = new System.Timers.Timer(150); // 150ms für schöne Animation
                                    animationTimer.Elapsed += (sender, e) =>
                                    {
                                        string animChar = animationChars[animationFrame % animationChars.Length];
                                        progressCallback("Phase 2/2", baseText + " " + animChar, 0);
                                        animationFrame++;
                                    };
                                    animationTimer.Start();
                                }
                            }
                            // Abschluss von STEP 1
                            else if (msg.StartsWith("[DONE:1]"))
                            {
                                animationTimer?.Stop();
                                animationTimer?.Dispose();
                                animationTimer = null;
                                animationFrame = 0;
                                var doneMessage = msg.Substring(8); // Entferne "[DONE:1]"
                                progressCallback("Phase 2/2", doneMessage, 0);
                            }
                            // STEP 2 - Nur Text anzeigen
                            else if (msg.StartsWith("[STEP2]"))
                            {
                                var textMessage = msg.Substring(7); // Entferne "[STEP2]"
                                progressCallback("Phase 2/2", textMessage, 0);
                            }
                            // Parse strukturierte Meldungen für STEP 3: [STEP:stepNr:aktuell:gesamt]Text
                            else if (msg.StartsWith("[STEP:"))
                            {
                                var endBracket = msg.IndexOf(']');
                                if (endBracket > 0)
                                {
                                    var stepInfo = msg.Substring(6, endBracket - 6);
                                    var stepParts = stepInfo.Split(':');
                                    var textMessage = msg.Substring(endBracket + 1);

                                    if (stepParts.Length == 3 &&
                                        int.TryParse(stepParts[0], out int step) &&
                                        int.TryParse(stepParts[1], out int current) &&
                                        int.TryParse(stepParts[2], out int total))
                                    {
                                        if (step == 3)
                                        {
                                            // Berechne Prozentsatz für STEP 3 (0-100%)
                                            int percent = total > 0 ? (current * 100) / total : 0;
                                            percent = Math.Min(100, Math.Max(0, percent));
                                            progressCallback("Phase 2/2", textMessage, percent);
                                        }
                                    }
                                }
                            }
                            // Legacy: Fallback auf alte Meldungen
                            else if (msg.Contains("Fertig:"))
                            {
                                progressCallback("Phase 2/2", msg, 100);
                            }
                        }
                        catch { }
                    };

                    _tsharkParser.ProgressChanged += phase2Handler;

                    var tsharkPackets = await _tsharkParser.ReadPcapFileAsync(filePath, cancellationToken);

                    _tsharkParser.ProgressChanged -= phase2Handler;

                    // Cleanup Animation Timer
                    animationTimer?.Stop();
                    animationTimer?.Dispose();

                    cancellationToken.ThrowIfCancellationRequested();

                    if (tsharkPackets.Count == 0)
                    {
                        AddLog("Phase 2: Übersprungen (TShark fand keine Pakete)");
                        IsPhase2Complete = true;
                        IsAnalysisReady = true;
                        IsLoading = false;
                        progressCallback("Phase 2/2", "Keine BACnet-Pakete gefunden", 100);
                        return (completePackets, statistics);
                    }

                    // Merge BACnet-Details
                    var packetIndex = new Dictionary<int, NetworkPacket>();
                    foreach (var p in completePackets)
                    {
                        if (!packetIndex.ContainsKey(p.PacketNumber))
                            packetIndex[p.PacketNumber] = p;
                    }

                    int enrichedCount = 0;
                    foreach (var tsharkPacket in tsharkPackets.Where(p => p.ApplicationProtocol == "BACnet" && p.Details.Count > 0))
                    {
                        if (packetIndex.TryGetValue(tsharkPacket.PacketNumber, out var existingPacket))
                        {
                            existingPacket.ApplicationProtocol = "BACnet";
                            foreach (var detail in tsharkPacket.Details)
                            {
                                existingPacket.Details[detail.Key] = detail.Value;
                            }
                            enrichedCount++;
                        }
                    }

                    if (_tsharkParser.BACnetDb.IpToInstance.Count > 0)
                    {
                        BacnetDatabase = _tsharkParser.BACnetDb;
                    }

                    AddLog($"✅ TShark: {enrichedCount} BACnet-Pakete mit Details angereichert");
                    IsPhase2Complete = true;
                    IsAnalysisReady = true;
                    IsLoading = false;
                    progressCallback("Phase 2/2", $"✅ {enrichedCount} Pakete analysiert", 100);
                }
                else
                {
                    IsPhase2Complete = true;
                    IsAnalysisReady = true;
                    IsLoading = false;
                }

                // Gib Pakete und Statistiken zurück für UI-Thread-Update
                return (completePackets, statistics);
            }
            catch (OperationCanceledException)
            {
                AddLog("⚠️ Import abgebrochen");
                IsLoading = false;
                return null;
            }
            catch (Exception ex)
            {
                AddLog($"FEHLER: {ex.Message}");
                IsLoading = false;
                throw;
            }
        }

        [RelayCommand]
        public async Task OpenPcapFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                return;

            try
            {
                IsLoading = true;
                IsPhase1Complete = false;
                IsPhase2Complete = false;
                IsAnalysisReady = false;
                LoadingMessage = "Lade Capture-Datei...";
                LoadProgress = 0;
                Phase1Progress = 0;
                Phase2Progress = 0;
                Phase1Message = "Phase 1: Starte...";
                Phase2Message = "Phase 2: Warte auf Phase 1";
                Packets.Clear();
                LoadedPacketCount = 0;

                AddLog($"Öffne Datei: {filePath}");

                // Phase 1: Mit SharpPcap alle Pakete einlesen (für Protokoll-Statistik)
                LoadingMessage = "Phase 1/2: Lese Pakete...";
                Phase1Message = "Phase 1: Lese Pakete ...";
                AddLog("Phase 1: Lese alle Pakete mit SharpPcap...");
                var packetList = await _sharpPcapReader.ReadPcapFileAsync(filePath);

                // Filtere reassemblierte Pakete (Fragmente) aus
                var completePackets = packetList.Where(p => !p.IsReassembled).ToList();
                var reassembledCount = packetList.Count - completePackets.Count;

                // Speichere BACnet-Datenbasis von SharpPcap
                BacnetDatabase = _sharpPcapReader.BACnetDb;

                IsPhase1Complete = true;
                Phase1Progress = 100;
                Phase1Message = "Phase 1: Abgeschlossen ✅";
                LoadProgress = _tsharkAvailable ? 50 : 100;
                LoadingMessage = _tsharkAvailable ? "Phase 1/2 abgeschlossen. Phase 2/2: TShark-Analyse läuft..." : "Fertig: Alle Pakete geladen";

                AddLog($"✅ SharpPcap: {completePackets.Count} komplette Pakete geladen");
                if (reassembledCount > 0)
                {
                    AddLog($"   Gefiltert: {reassembledCount} fragmentierte Pakete");
                }

                // Populate ObservableCollection ASYNCHRON auf dem UI-Thread (batch updates)
                // Verwende Task um UI nicht zu blockieren
                _ = Task.Run(() =>
                {
                    _synchronizationContext.Post(_ =>
                    {
                        // Batch-Add: Deaktiviere Updates während wir Pakete hinzufügen
                        foreach (var packet in completePackets)
                        {
                            Packets.Add(packet);
                        }

                        // Calculate statistics
                        PacketStatistics = _statsCalculator.CalculateStatistics(packetList);
                    }, null);
                });

                // Phase 2: Falls TShark verfügbar, BACnet-Details anreichern
                // TShark analysiert UNABHÄNGIG und sucht nach BACnet-Paketen
                if (_tsharkAvailable && _tsharkParser != null)
                {
                    LoadingMessage = "Phase 2/2: Analysiere BACnet-Details...";
                    Phase2Message = "Phase 2: Starte BACnet-Analyse...";
                    Phase2Progress = 0;
                    AddLog("Phase 2: Analysiere BACnet-Details mit TShark...");

                    // TShark-Analyse im Hintergrund, nicht blockierend
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            var tsharkPackets = await _tsharkParser.ReadPcapFileAsync(filePath);

                            if (tsharkPackets.Count == 0)
                            {
                                _synchronizationContext.Post(_ =>
                                {
                                    AddLog("Phase 2: Übersprungen (TShark fand keine Pakete)");
                                    IsPhase2Complete = true;
                                    IsAnalysisReady = true;
                                    IsLoading = false;
                                    LoadProgress = 100;
                                    Phase2Progress = 100;
                                    Phase2Message = "Phase 2: Keine BACnet-Pakete gefunden";
                                    LoadingMessage = "Fertig: Alle Pakete geladen (TShark: keine BACnet-Pakete)";
                                }, null);
                                return;
                            }

                            // Erstelle Index für schnellere Suche
                            var packetIndex = new Dictionary<int, NetworkPacket>();
                            foreach (var p in completePackets)
                            {
                                if (!packetIndex.ContainsKey(p.PacketNumber))
                                    packetIndex[p.PacketNumber] = p;
                            }

                            // Merge BACnet-Details in bestehende Pakete
                            int enrichedCount = 0;
                            _synchronizationContext.Post(_ =>
                            {
                                Phase2Message = $"Phase 2: Merge {tsharkPackets.Count:N0} Pakete...";
                                Phase2Progress = 95;
                            }, null);
                            foreach (var tsharkPacket in tsharkPackets.Where(p => p.ApplicationProtocol == "BACnet" && p.Details.Count > 0))
                            {
                                // Nutze Index für O(1) Zugriff statt O(n) FirstOrDefault
                                if (packetIndex.TryGetValue(tsharkPacket.PacketNumber, out var existingPacket))
                                {
                                    // Überschreibe/ergänze BACnet-Details
                                    existingPacket.ApplicationProtocol = "BACnet";
                                    foreach (var detail in tsharkPacket.Details)
                                    {
                                        existingPacket.Details[detail.Key] = detail.Value;
                                    }
                                    enrichedCount++;
                                }
                            }

                            // Aktualisiere BACnet-Datenbasis mit TShark-Daten
                            // TShark liefert oft detailliertere Daten als SharpPcap
                            if (_tsharkParser.BACnetDb.IpToInstance.Count > 0)
                            {
                                BacnetDatabase = _tsharkParser.BACnetDb;

                                _synchronizationContext.Post(_ =>
                                {
                                    AddLog($"✅ TShark: {enrichedCount} BACnet-Pakete mit Details angereichert");
                                    var summary = $"┌── BACnet-Datenbasis ({BacnetDatabase.IpToInstance.Count} Geräte - TShark) ──┐";
                                    AddLog(summary);
                                    IsPhase2Complete = true;
                                    IsAnalysisReady = true;
                                    IsLoading = false;
                                    LoadProgress = 100;
                                    Phase2Progress = 100;
                                    Phase2Message = $"Phase 2: Abgeschlossen ✅ ({enrichedCount} Pakete)";
                                    LoadingMessage = $"Fertig: {enrichedCount} BACnet-Pakete mit TShark analysiert";
                                }, null);
                            }
                            else if (enrichedCount > 0)
                            {
                                _synchronizationContext.Post(_ =>
                                {
                                    AddLog($"✅ TShark: {enrichedCount} BACnet-Pakete mit Details angereichert (keine Geräte identifiziert)");
                                    IsPhase2Complete = true;
                                    IsAnalysisReady = true;
                                    IsLoading = false;
                                    LoadProgress = 100;
                                    Phase2Progress = 100;
                                    Phase2Message = $"Phase 2: Abgeschlossen ✅ ({enrichedCount} Pakete)";
                                    LoadingMessage = $"Fertig: {enrichedCount} BACnet-Pakete mit TShark analysiert";
                                }, null);
                            }
                            else
                            {
                                _synchronizationContext.Post(_ =>
                                {
                                    AddLog($"⚠️  TShark: Keine BACnet-Details extrahiert");
                                    IsPhase2Complete = true;
                                    IsAnalysisReady = true;
                                    IsLoading = false;
                                    LoadProgress = 100;
                                    Phase2Progress = 100;
                                    Phase2Message = "Phase 2: Keine Details extrahiert";
                                    LoadingMessage = "Fertig: TShark-Analyse abgeschlossen (keine Details)";
                                }, null);
                            }
                        }
                        catch (Exception ex)
                        {
                            _synchronizationContext.Post(_ =>
                            {
                                AddLog($"⚠️  TShark-Analyse fehlgeschlagen: {ex.Message}");
                                IsPhase2Complete = true;
                                IsAnalysisReady = true;
                                IsLoading = false;
                                LoadProgress = 100;
                                Phase2Progress = 100;
                                Phase2Message = "Phase 2: Fehlgeschlagen ⚠️";
                                LoadingMessage = "Fertig: TShark-Analyse fehlgeschlagen";
                            }, null);
                        }
                    });
                }

                // BACnet-Datenbasis-Statistik ausgeben (SharpPcap - nur wenn TShark nicht aktiv ist)
                if (!_tsharkAvailable || _tsharkParser == null)
                {
                    if (BacnetDatabase?.IpToInstance.Count > 0)
                    {
                        var summary = $"┌── BACnet-Datenbasis ({BacnetDatabase.IpToInstance.Count} Geräte - SharpPcap) ──┐";
                        AddLog(summary);
                    }
                    else
                    {
                        AddLog($"BACnet-Datenbasis: Keine BACnet-Geräte gefunden");
                    }
                    IsPhase2Complete = true;
                    IsAnalysisReady = true;
                    IsLoading = false;
                    Phase2Message = "Phase 2: Nicht verfügbar (TShark fehlt)";
                    Phase2Progress = 0;
                    LoadingMessage = $"Fertig: {completePackets.Count} Pakete geladen";
                }
                // Wenn TShark aktiv ist, werden die Ergebnisse asynchron in Phase 2 ausgegeben
            }
            catch (Exception ex)
            {
                AddLog($"FEHLER: {ex.Message}");
                IsLoading = false;
            }
        }

        [RelayCommand]
        public void FilterPackets(string filterText)
        {
            // Implement filtering logic
            AddLog($"Filter angewendet: {filterText}");
        }

        [RelayCommand]
        public void ExportStatistics(string exportPath)
        {
            // Implement export logic
            AddLog($"Statistiken exportieren nach: {exportPath}");
        }

        private void OnProgressChanged(object? sender, string message)
        {
            LoadingMessage = message;
            Phase1Message = message;
            AddLog(message);

            // Versuche Progress-Prozentsatz aus der Nachricht zu extrahieren (z.B. "Gelesen: 50000 von 100000 Paketen (50%)")
            if (message.Contains("(") && message.Contains("%"))
            {
                try
                {
                    int percentStart = message.LastIndexOf('(');
                    int percentEnd = message.LastIndexOf('%');
                    if (percentStart >= 0 && percentEnd > percentStart)
                    {
                        string percentStr = message.Substring(percentStart + 1, percentEnd - percentStart - 1);
                        if (int.TryParse(percentStr, out int percent))
                        {
                            Phase1Progress = Math.Min(100, percent); // Max 100%
                            LoadProgress = Math.Min(100, percent);
                        }
                    }
                }
                catch { }
            }
        }

        private void OnPhase2ProgressChanged(object? sender, string message)
        {
            AddLog($"Phase 2: {message}");

            // Verarbeite verschiedene TShark-Meldungen
            if (message.StartsWith("Verarbeitet:"))
            {
                // "Verarbeitet: 5000 Pakete" → extrahiere Anzahl
                try
                {
                    var parts = message.Split(' ');
                    if (parts.Length >= 2 && int.TryParse(parts[1], out int count))
                    {
                        Phase2Message = $"Phase 2: Gelesen: {count:N0} Pakete";
                        // Schätze Fortschritt basierend auf Paketzahl (maximal 90%)
                        Phase2Progress = Math.Min(90, (count / 1000) * 2); // Jedes 1000 Pakete = 2%
                    }
                }
                catch { }
            }
            else if (message.StartsWith("Fertig:"))
            {
                // "Fertig: 12345 Pakete gelesen"
                try
                {
                    var parts = message.Split(' ');
                    if (parts.Length >= 2 && int.TryParse(parts[1], out int count))
                    {
                        Phase2Message = $"Phase 2: {count:N0} Pakete gelesen";
                        Phase2Progress = 95;
                    }
                }
                catch { }
            }
            else if (message.StartsWith("Starte"))
            {
                Phase2Message = "Phase 2: Lese Pakete ...";
            }
            else if (message.StartsWith("Parse"))
            {
                // Parse JSON-Daten entfällt - wird nicht angezeigt
                Phase2Message = "Phase 2: Lese Pakete ...";
            }
            else if (message.Contains("TShark") || message.Contains("JSON"))
            {
                Phase2Message = "Phase 2: Lese Pakete ...";
            }
        }

        public void AddUiLog(string message) => AddLog(message);

        private void AddLog(string message)
        {
            // Filtere Phase-Updates (immer - nicht konfigurierbar)
            if (message.Contains("Phase") || message.Contains("Übersprungen"))
                return;

            // Filtere Progress-Meldungen (Gelesen: x von y Paketen)
            if (message.Contains("Gelesen:") && message.Contains("von") && message.Contains("Paketen"))
                return;

            // Filtere [STEP2] und [STEP3] Meldungen (JSON-Lesen und Paketverarbeitung)
            if (message.Contains("[STEP2]") || message.Contains("[STEP3") || message.Contains("Verarbeite"))
                return;

            var now = DateTime.Now;
            var baseMsg = message?.Trim() ?? string.Empty;

            _synchronizationContext.Post(_ =>
            {
                if (string.Equals(_lastLogBase, baseMsg, StringComparison.Ordinal))
                {
                    _lastLogRepeatCount++;
                    // Update letzte Zeile statt neue anzuhängen
                    if (LogMessages.Count > 0)
                    {
                        // Behalte ursprünglichen Zeitstempel der letzten Zeile
                        var last = LogMessages[LogMessages.Count - 1];
                        var idx = last.IndexOf(']');
                        var ts = idx > 0 ? last.Substring(0, idx + 1) : $"[{now:HH:mm:ss}]";
                        LogMessages[LogMessages.Count - 1] = $"{ts} {baseMsg} (x{_lastLogRepeatCount})";
                    }
                }
                else
                {
                    _lastLogBase = baseMsg;
                    _lastLogTime = now;
                    _lastLogRepeatCount = 1;

                    LogMessages.Add($"[{now:HH:mm:ss}] {baseMsg}");

                    // Keep only last 200 messages (stark reduziert)
                    while (LogMessages.Count > 200)
                        LogMessages.RemoveAt(0);
                }
            }, null);
        }
    }
}
