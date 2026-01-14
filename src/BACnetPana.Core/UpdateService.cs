using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace BACnetPana.Core
{
    /// <summary>
    /// Service für Update-Überprüfung gegen GitHub Releases
    /// </summary>
    public class UpdateService
    {
        private const string GitHubApiUrl = "https://api.github.com/repos/Flecky13/BACnetPana/releases/latest";
        private const string GitHubRepoUrl = "https://github.com/Flecky13/BACnetPana/releases";
        private const string CurrentVersion = "1.3.0.0";
        private const string AppName = "BACnetPana";
        private const string Author = "Flecky13";

        public class VersionInfo
        {
            public string? CurrentVersion { get; set; }
            public string? LatestVersion { get; set; }
            public string? DownloadUrl { get; set; }
            public string? ReleaseNotes { get; set; }
            public bool UpdateAvailable { get; set; }
            public string? Author { get; set; }
            public DateTime? ReleaseDate { get; set; }
        }

        /// <summary>
        /// Prüft die neueste verfügbare Version auf GitHub
        /// </summary>
        public async Task<VersionInfo> CheckForUpdatesAsync()
        {
            var versionInfo = new VersionInfo
            {
                CurrentVersion = CurrentVersion,
                Author = Author,
                UpdateAvailable = false
            };

            try
            {
                using var httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Add("User-Agent", $"{AppName}/{CurrentVersion}");

                var response = await httpClient.GetAsync(GitHubApiUrl);
                if (!response.IsSuccessStatusCode)
                {
                    System.Diagnostics.Debug.WriteLine($"[UpdateService] GitHub API Fehler: {response.StatusCode}");
                    return versionInfo;
                }

                var json = await response.Content.ReadAsStringAsync();
                using var jsonDoc = JsonDocument.Parse(json);
                var root = jsonDoc.RootElement;

                // Extrahiere Version aus dem Tag-Namen (z.B. "v1.4.0" -> "1.4.0")
                if (root.TryGetProperty("tag_name", out var tagElement))
                {
                    var tagName = tagElement.GetString();
                    versionInfo.LatestVersion = tagName?.TrimStart('v') ?? CurrentVersion;

                    // Prüfe ob Update verfügbar ist
                    if (CompareVersions(versionInfo.LatestVersion, CurrentVersion) > 0)
                    {
                        versionInfo.UpdateAvailable = true;
                    }
                }

                // Extrahiere Download-URL
                if (root.TryGetProperty("assets", out var assetsElement) && assetsElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var asset in assetsElement.EnumerateArray())
                    {
                        if (asset.TryGetProperty("browser_download_url", out var urlElement))
                        {
                            var url = urlElement.GetString();
                            // Suche nach .exe oder .zip Datei
                            if (url?.Contains(".exe") == true || url?.Contains(".zip") == true)
                            {
                                versionInfo.DownloadUrl = url;
                                break;
                            }
                        }
                    }
                }

                // Extrahiere Release Notes
                if (root.TryGetProperty("body", out var bodyElement))
                {
                    versionInfo.ReleaseNotes = bodyElement.GetString() ?? string.Empty;
                }

                // Extrahiere Release Date
                if (root.TryGetProperty("published_at", out var dateElement))
                {
                    if (DateTime.TryParse(dateElement.GetString(), out var releaseDate))
                    {
                        versionInfo.ReleaseDate = releaseDate;
                    }
                }

                System.Diagnostics.Debug.WriteLine($"[UpdateService] Update-Check erfolgreich. Neueste Version: {versionInfo.LatestVersion}, Update verfügbar: {versionInfo.UpdateAvailable}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Fehler beim Update-Check: {ex.Message}");
            }

            return versionInfo;
        }

        /// <summary>
        /// Downloadet die neueste Version
        /// </summary>
        public async Task<bool> DownloadUpdateAsync(string downloadUrl, string savePath)
        {
            try
            {
                using var httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Add("User-Agent", $"{AppName}/{CurrentVersion}");

                var response = await httpClient.GetAsync(downloadUrl);
                if (!response.IsSuccessStatusCode)
                {
                    System.Diagnostics.Debug.WriteLine($"[UpdateService] Download Fehler: {response.StatusCode}");
                    return false;
                }

                var content = await response.Content.ReadAsByteArrayAsync();
                await File.WriteAllBytesAsync(savePath, content);

                System.Diagnostics.Debug.WriteLine($"[UpdateService] Download erfolgreich: {savePath}");
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Download-Fehler: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Öffnet die GitHub Release-Seite im Browser
        /// </summary>
        public void OpenGitHubReleasePage()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = GitHubRepoUrl,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Fehler beim Öffnen der Release-Seite: {ex.Message}");
            }
        }

        /// <summary>
        /// Vergleicht zwei Versionsnummern
        /// </summary>
        /// <returns>-1 wenn v1 < v2, 0 wenn gleich, 1 wenn v1 > v2</returns>
        private int CompareVersions(string v1, string v2)
        {
            try
            {
                var version1 = new Version(v1);
                var version2 = new Version(v2);
                return version1.CompareTo(version2);
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Gibt Informationen über die Anwendung zurück
        /// </summary>
        public VersionInfo GetApplicationInfo()
        {
            return new VersionInfo
            {
                CurrentVersion = CurrentVersion,
                Author = Author,
                UpdateAvailable = false,
                LatestVersion = CurrentVersion
            };
        }
    }
}
