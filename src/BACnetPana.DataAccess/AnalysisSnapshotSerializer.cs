using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using BACnetPana.Models;

namespace BACnetPana.DataAccess
{
    /// <summary>
    /// Speichert und lädt Analysezustände als komprimierte JSON-Dateien
    /// Optimiert für große Datenmengen durch Streaming-Serialisierung
    /// </summary>
    public class AnalysisSnapshotSerializer
    {
        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            WriteIndented = false, // Kompakt für kleinere Dateien
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            DefaultBufferSize = 65536 // 64KB Buffer für Streaming
        };

        private const int PACKET_BATCH_SIZE = 10000; // Pakete in Chunks speichern
        private const int PROGRESS_UPDATE_INTERVAL = 50000; // Progress alle 50k Pakete

        public event EventHandler<(int current, int total)>? ProgressChanged;

        /// <summary>
        /// Speichert einen Analysezustand (nur BACnet-Pakete + Statistiken)
        /// Verwendet Streaming für große Datenmengen
        /// </summary>
        public async Task SaveAsync(string filePath, AnalysisSnapshot snapshot, bool onlyBacnetPackets = true)
        {
            try
            {
                // Filtere nur BACnet-Pakete wenn gewünscht (MASSIV schneller!)
                var packetsToSave = snapshot.Packets;
                if (onlyBacnetPackets && snapshot.Packets != null)
                {
                    packetsToSave = snapshot.Packets
                        .Where(p => p.ApplicationProtocol == "BACnet" ||
                                   p.DestinationPort == 47808 || p.SourcePort == 47808)
                        .ToList();
                }

                int totalPackets = packetsToSave?.Count ?? 0;

                using var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 65536);
                using var gzipStream = new GZipStream(fileStream, CompressionLevel.Optimal);
                using var writer = new StreamWriter(gzipStream, System.Text.Encoding.UTF8, 65536, leaveOpen: false);

                // Schreibe strukturiertes JSON mit Streaming
                await writer.WriteAsync("{");
                await writer.WriteLineAsync();

                // Metadaten
                await writer.WriteAsync($"  \"version\": \"{snapshot.Version}\",");
                await writer.WriteLineAsync();
                await writer.WriteAsync($"  \"createdAt\": \"{snapshot.CreatedAt:o}\",");
                await writer.WriteLineAsync();
                await writer.WriteAsync($"  \"onlyBacnetPackets\": {onlyBacnetPackets.ToString().ToLower()},");
                await writer.WriteLineAsync();

                if (!string.IsNullOrEmpty(snapshot.OriginalPcapFile))
                {
                    string escapedPath = snapshot.OriginalPcapFile.Replace("\\", "\\\\").Replace("\"", "\\\"");
                    await writer.WriteAsync($"  \"originalPcapFile\": \"{escapedPath}\",");
                    await writer.WriteLineAsync();
                }

                // Statistiken
                if (snapshot.Statistics != null)
                {
                    await writer.WriteAsync("  \"statistics\": ");
                    var statsJson = JsonSerializer.Serialize(snapshot.Statistics, JsonOptions);
                    await writer.WriteAsync(statsJson);
                    await writer.WriteAsync(",");
                    await writer.WriteLineAsync();
                }

                // BACnet-Datenbank
                if (snapshot.BacnetDb != null)
                {
                    await writer.WriteAsync("  \"bacnetDb\": ");
                    var dbJson = JsonSerializer.Serialize(snapshot.BacnetDb, JsonOptions);
                    await writer.WriteAsync(dbJson);
                    await writer.WriteAsync(",");
                    await writer.WriteLineAsync();
                }

                // Pakete in Batches
                await writer.WriteAsync("  \"packets\": [");
                await writer.WriteLineAsync();

                if (packetsToSave != null && packetsToSave.Count > 0)
                {
                    for (int i = 0; i < packetsToSave.Count; i++)
                    {
                        var packet = packetsToSave[i];
                        var packetJson = JsonSerializer.Serialize(packet, JsonOptions);
                        await writer.WriteAsync("    ");
                        await writer.WriteAsync(packetJson);

                        if (i < packetsToSave.Count - 1)
                            await writer.WriteAsync(",");

                        await writer.WriteLineAsync();

                        // Flush regelmäßig für große Dateien
                        if ((i + 1) % PACKET_BATCH_SIZE == 0)
                        {
                            await writer.FlushAsync();
                        }

                        // Progress-Update
                        if ((i + 1) % PROGRESS_UPDATE_INTERVAL == 0 || i == packetsToSave.Count - 1)
                        {
                            ProgressChanged?.Invoke(this, (i + 1, totalPackets));
                        }
                    }
                }

                await writer.WriteLineAsync("  ]");
                await writer.WriteAsync("}");
                await writer.FlushAsync();
            }
            catch (OutOfMemoryException ex)
            {
                throw new Exception($"Nicht genug Speicher zum Speichern. " +
                    $"Versuchen Sie eine kleinere PCAP-Datei zu analysieren. " +
                    $"Details: {ex.Message}", ex);
            }
            catch (IOException ex)
            {
                throw new Exception($"Fehler beim Schreiben der Datei: {ex.Message}. " +
                    $"Prüfen Sie, dass genug Speicherplatz verfügbar ist.", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"Fehler beim Speichern der Analyse: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Lädt einen gespeicherten Analysezustand
        /// Optimiert für große Datenmengen
        /// </summary>
        public async Task<AnalysisSnapshot> LoadAsync(string filePath)
        {
            try
            {
                using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536);
                using var gzipStream = new GZipStream(fileStream, CompressionMode.Decompress);

                // Lies JSON und deserialisiere
                using var document = JsonDocument.Parse(gzipStream);
                var root = document.RootElement;

                var snapshot = new AnalysisSnapshot();

                // Metadaten
                if (root.TryGetProperty("version", out var versionEl))
                    snapshot.Version = versionEl.GetString() ?? "1.0";

                if (root.TryGetProperty("createdAt", out var dateEl) && DateTime.TryParse(dateEl.GetString(), out var createdAt))
                    snapshot.CreatedAt = createdAt;

                if (root.TryGetProperty("originalPcapFile", out var pcapEl))
                    snapshot.OriginalPcapFile = pcapEl.GetString();

                // Statistiken
                if (root.TryGetProperty("statistics", out var statsEl))
                {
                    snapshot.Statistics = JsonSerializer.Deserialize<PacketStatistics>(statsEl.GetRawText(), JsonOptions);
                }

                // BACnet-Datenbank
                if (root.TryGetProperty("bacnetDb", out var dbEl))
                {
                    snapshot.BacnetDb = JsonSerializer.Deserialize<AnalysisSnapshot.BACnetDatabaseSnapshot>(dbEl.GetRawText(), JsonOptions);
                }

                // Pakete
                if (root.TryGetProperty("packets", out var packetsEl) && packetsEl.ValueKind == JsonValueKind.Array)
                {
                    snapshot.Packets = new List<NetworkPacket>();
                    foreach (var packetEl in packetsEl.EnumerateArray())
                    {
                        var packet = JsonSerializer.Deserialize<NetworkPacket>(packetEl.GetRawText(), JsonOptions);
                        if (packet != null)
                            snapshot.Packets.Add(packet);
                    }
                }

                return snapshot;
            }
            catch (OutOfMemoryException ex)
            {
                throw new Exception($"Nicht genug Speicher zum Laden. " +
                    $"Die Datei ist zu groß. Details: {ex.Message}", ex);
            }
            catch (IOException ex)
            {
                throw new Exception($"Fehler beim Lesen der Datei: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"Fehler beim Laden der Analyse: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Prüft ob eine Datei ein gültiges Analyse-Snapshot ist
        /// </summary>
        public bool IsValidSnapshot(string filePath)
        {
            try
            {
                using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var gzipStream = new GZipStream(fileStream, CompressionMode.Decompress);
                using var reader = new StreamReader(gzipStream, System.Text.Encoding.UTF8);

                string json = reader.ReadToEnd();
                var snapshot = JsonSerializer.Deserialize<AnalysisSnapshot>(json, JsonOptions);

                return snapshot != null && snapshot.Version != null;
            }
            catch
            {
                return false;
            }
        }
    }
}
