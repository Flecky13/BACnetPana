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
        private BACnetDatabase? bacnetDatabase;

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

        [RelayCommand]
        public async Task OpenPcapFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                return;

            try
            {
                IsLoading = true;
                LoadingMessage = "Lade Capture-Datei...";
                Packets.Clear();
                LoadedPacketCount = 0;

                AddLog($"Öffne Datei: {filePath}");

                // Phase 1: Mit SharpPcap alle Pakete einlesen (für Protokoll-Statistik)
                AddLog("Phase 1: Lese alle Pakete mit SharpPcap...");
                var packetList = await _sharpPcapReader.ReadPcapFileAsync(filePath);

                // Filtere reassemblierte Pakete (Fragmente) aus
                var completePackets = packetList.Where(p => !p.IsReassembled).ToList();
                var reassembledCount = packetList.Count - completePackets.Count;

                // Speichere BACnet-Datenbasis von SharpPcap
                BacnetDatabase = _sharpPcapReader.BACnetDb;

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
                                }, null);
                            }
                            else if (enrichedCount > 0)
                            {
                                _synchronizationContext.Post(_ =>
                                {
                                    AddLog($"✅ TShark: {enrichedCount} BACnet-Pakete mit Details angereichert (keine Geräte identifiziert)");
                                }, null);
                            }
                            else
                            {
                                _synchronizationContext.Post(_ =>
                                {
                                    AddLog($"⚠️  TShark: Keine BACnet-Details extrahiert");
                                }, null);
                            }
                        }
                        catch (Exception ex)
                        {
                            _synchronizationContext.Post(_ =>
                            {
                                AddLog($"⚠️  TShark-Analyse fehlgeschlagen: {ex.Message}");
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
                }
                // Wenn TShark aktiv ist, werden die Ergebnisse asynchron in Phase 2 ausgegeben

                LoadingMessage = $"Fertig: {completePackets.Count} Pakete geladen";
            }
            catch (Exception ex)
            {
                AddLog($"FEHLER: {ex.Message}");
            }
            finally
            {
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
                            LoadProgress = Math.Min(100, percent); // Max 100%
                        }
                    }
                }
                catch { }
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
    }
}
