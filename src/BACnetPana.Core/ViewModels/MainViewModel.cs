using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BACnetPana.Models;
using BACnetPana.DataAccess;

namespace BACnetPana.Core.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        private readonly PcapFileReader _sharpPcapReader;
        private TSharkBACnetParser? _tsharkParser;
        private bool _tsharkAvailable = false;
        private readonly StatisticsCalculator _statsCalculator;
        private readonly AnalysisSnapshotSerializer _snapshotSerializer;
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
        private bool hasAnalysisData;

        [ObservableProperty]
        private string? currentAnalysisFile;

        public MainViewModel()
        {
            // Immer SharpPcap für das generelle Parsing verwenden
            _sharpPcapReader = new PcapFileReader();
            _statsCalculator = new StatisticsCalculator();
            _snapshotSerializer = new AnalysisSnapshotSerializer();
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

                    progressCallback("Phase 2/2", "Analysiere BACnet-Details mit TShark...", 0);
                    AddLog("Phase 2: Analysiere BACnet-Details mit TShark...");

                    EventHandler<string>? phase2Handler = (s, msg) =>
                    {
                        if (msg.StartsWith("Verarbeitet:"))
                        {
                            try
                            {
                                var parts = msg.Split(' ');
                                if (parts.Length >= 2 && int.TryParse(parts[1], out int count))
                                {
                                    int estimatedPercent = Math.Min(90, (count / 1000) * 2);
                                    progressCallback("Phase 2/2", $"Gelesen: {count:N0} Pakete", estimatedPercent);
                                }
                            }
                            catch { }
                        }
                    };

                    _tsharkParser.ProgressChanged += phase2Handler;

                    var tsharkPackets = await _tsharkParser.ReadPcapFileAsync(filePath, cancellationToken);

                    _tsharkParser.ProgressChanged -= phase2Handler;

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
                    HasAnalysisData = true;
                    IsLoading = false;
                    progressCallback("Phase 2/2", $"✅ {enrichedCount} Pakete analysiert", 100);
                }
                else
                {
                    IsPhase2Complete = true;
                    IsAnalysisReady = true;
                    HasAnalysisData = true;
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

        private void AddLog(string message)
        {
            var logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";

            // Auf dem UI-Thread ausführen
            _synchronizationContext.Post(_ =>
            {
                LogMessages.Add(logEntry);

                // Keep only last 1000 messages
                while (LogMessages.Count > 1000)
                    LogMessages.RemoveAt(0);
            }, null);
        }
        /// <summary>
        /// Speichert den aktuellen Analysezustand in eine Datei
        /// </summary>
        public async Task<bool> SaveAnalysisAsync(string filePath, bool onlyBacnetPackets = true)
        {
            try
            {
                if (Packets == null || Packets.Count == 0)
                {
                    AddLog("❌ Keine Daten zum Speichern vorhanden");
                    return false;
                }

                int bacnetCount = Packets.Count(p => p.ApplicationProtocol == "BACnet" ||
                                                      p.DestinationPort == 47808 ||
                                                      p.SourcePort == 47808);

                if (onlyBacnetPackets && bacnetCount > 0)
                {
                    AddLog($"💾 Speichere Analyse (nur {bacnetCount:N0} BACnet-Pakete von {Packets.Count:N0})");
                }
                else
                {
                    AddLog($"💾 Speichere Analyse ({Packets.Count:N0} Pakete)");
                }

                IsLoading = true;
                LoadingMessage = "Speichere Analyse...";

                var snapshot = new AnalysisSnapshot
                {
                    OriginalPcapFile = CurrentAnalysisFile,
                    Packets = Packets.ToList(),
                    Statistics = PacketStatistics,
                    BacnetDb = BacnetDatabase != null
                        ? AnalysisSnapshot.BACnetDatabaseSnapshot.FromBACnetDatabase(BacnetDatabase)
                        : null
                };

                // Progress-Handler
                _snapshotSerializer.ProgressChanged += (s, progress) =>
                {
                    int percent = progress.total > 0 ? (progress.current * 100 / progress.total) : 0;
                    LoadingMessage = $"Speichere: {progress.current:N0} / {progress.total:N0} Pakete ({percent}%)";
                };

                await _snapshotSerializer.SaveAsync(filePath, snapshot, onlyBacnetPackets);

                int savedCount = onlyBacnetPackets ? bacnetCount : Packets.Count;
                AddLog($"✅ Analyse gespeichert ({savedCount:N0} Pakete)");
                AddLog($"    Datei: {System.IO.Path.GetFileName(filePath)}");

                var fileInfo = new System.IO.FileInfo(filePath);
                AddLog($"    Größe: {fileInfo.Length / 1024 / 1024:N1} MB");

                return true;
            }
            catch (Exception ex)
            {
                AddLog($"❌ Fehler beim Speichern: {ex.Message}");
                return false;
            }
            finally
            {
                IsLoading = false;
                LoadingMessage = string.Empty;
            }
        }

        /// <summary>
        /// Lädt einen gespeicherten Analysezustand aus einer Datei
        /// </summary>
        public async Task<bool> LoadAnalysisAsync(string filePath)
        {
            try
            {
                AddLog($"📂 Lade Analyse von: {filePath}");
                IsLoading = true;
                LoadingMessage = "Lade Analyse...";

                var snapshot = await _snapshotSerializer.LoadAsync(filePath);

                // Übernehme Daten ins ViewModel
                Packets.Clear();
                foreach (var packet in snapshot.Packets)
                {
                    Packets.Add(packet);
                }

                if (snapshot.Statistics != null)
                {
                    PacketStatistics = snapshot.Statistics;
                }

                if (snapshot.BacnetDb != null)
                {
                    BacnetDatabase = snapshot.BacnetDb.ToBACnetDatabase();
                }

                CurrentAnalysisFile = snapshot.OriginalPcapFile;
                LoadedPacketCount = Packets.Count;
                IsPhase1Complete = true;
                IsPhase2Complete = true;
                IsAnalysisReady = true;
                HasAnalysisData = true;

                AddLog($"✅ Analyse geladen ({Packets.Count:N0} Pakete)");
                AddLog($"    Erstellt: {snapshot.CreatedAt:dd.MM.yyyy HH:mm}");
                if (!string.IsNullOrEmpty(snapshot.OriginalPcapFile))
                {
                    AddLog($"    Original: {System.IO.Path.GetFileName(snapshot.OriginalPcapFile)}");
                }

                return true;
            }
            catch (Exception ex)
            {
                AddLog($"❌ Fehler beim Laden: {ex.Message}");
                return false;
            }
            finally
            {
                IsLoading = false;
                LoadingMessage = string.Empty;
            }
        }    }
}
