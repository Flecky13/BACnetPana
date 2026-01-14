using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace bacneTPana.Core
{
    /// <summary>
    /// Service für Update-Überprüfung gegen GitHub Releases
    /// </summary>
    public class UpdateService
    {
        private const string GitHubApiLatestUrl = "https://api.github.com/repos/Flecky13/bacneTPana/releases/latest";
        private const string GitHubApiAllReleasesUrl = "https://api.github.com/repos/Flecky13/bacneTPana/releases";
        private const string GitHubRepoUrl = "https://github.com/Flecky13/bacneTPana/releases";
        private static string CurrentVersion = GetCurrentVersion();
        private const string AppName = "bacneTPana";
        private const string Author = "Flecky13";

        /// <summary>
        /// Liest die aktuelle Version aus der Assembly
        /// </summary>
        private static string GetCurrentVersion()
        {
            try
            {
                var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                if (version != null)
                {
                    return $"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}";
                }
            }
            catch { }

            // Fallback
            return "1.0.0.0";
        }

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
                httpClient.Timeout = TimeSpan.FromSeconds(10);
                httpClient.DefaultRequestHeaders.Add("User-Agent", $"{AppName}/{CurrentVersion}");

                System.Diagnostics.Debug.WriteLine($"[UpdateService] Prüfe auf Updates... CurrentVersion: {CurrentVersion}");

                // Versuche zuerst latest endpoint
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Versuche /latest endpoint");
                var json = await TryGetReleaseJson(httpClient, GitHubApiLatestUrl);

                // Falls leer (z.B. nur Drafts/Pre-releases), versuche alle releases
                if (string.IsNullOrEmpty(json))
                {
                    System.Diagnostics.Debug.WriteLine($"[UpdateService] /latest leer, versuche alle releases");
                    json = await TryGetReleaseJsonFromAll(httpClient, GitHubApiAllReleasesUrl);
                }

                if (string.IsNullOrEmpty(json))
                {
                    System.Diagnostics.Debug.WriteLine($"[UpdateService] Keine Release-Daten gefunden");
                    return versionInfo;
                }

                // Parse JSON
                ParseReleaseInfo(json, versionInfo);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Fehler beim Update-Check: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Stack-Trace: {ex.StackTrace}");
            }

            return versionInfo;
        }

        /// <summary>
        /// Versucht, den /latest Endpoint zu lesen
        /// </summary>
        private async Task<string> TryGetReleaseJson(HttpClient httpClient, string url)
        {
            try
            {
                var response = await httpClient.GetAsync(url);
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    System.Diagnostics.Debug.WriteLine($"[UpdateService] Response von {url}: {json.Length} Bytes");
                    return json;
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[UpdateService] Fehler bei {url}: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Fehler beim Abrufen von {url}: {ex.Message}");
            }

            return string.Empty;
        }

        /// <summary>
        /// Versucht, aus dem /releases Array die neueste Release zu finden
        /// </summary>
        private async Task<string> TryGetReleaseJsonFromAll(HttpClient httpClient, string url)
        {
            try
            {
                var response = await httpClient.GetAsync(url);
                if (!response.IsSuccessStatusCode)
                {
                    System.Diagnostics.Debug.WriteLine($"[UpdateService] Fehler bei {url}: {response.StatusCode}");
                    return string.Empty;
                }

                var json = await response.Content.ReadAsStringAsync();
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Response von {url}: {json.Length} Bytes");

                using var jsonDoc = JsonDocument.Parse(json);
                var root = jsonDoc.RootElement;

                if (root.ValueKind == JsonValueKind.Array && root.GetArrayLength() > 0)
                {
                    // Finde die neueste nicht-Draft Release
                    foreach (var release in root.EnumerateArray())
                    {
                        bool isDraft = false;
                        if (release.TryGetProperty("draft", out var draftProp))
                        {
                            isDraft = draftProp.GetBoolean();
                        }

                        if (!isDraft && release.TryGetProperty("tag_name", out _))
                        {
                            // Gib diese Release als JSON zurück
                            return release.GetRawText();
                        }
                    }
                }

                System.Diagnostics.Debug.WriteLine($"[UpdateService] Keine gültige Release im Array gefunden");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Fehler beim Abrufen aller Releases: {ex.Message}");
            }

            return string.Empty;
        }

        /// <summary>
        /// Parst die Release-Informationen aus dem JSON
        /// </summary>
        private void ParseReleaseInfo(string json, VersionInfo versionInfo)
        {
            using var jsonDoc = JsonDocument.Parse(json);
            var root = jsonDoc.RootElement;

            // Extrahiere Version aus dem Tag-Namen (z.B. "v1.4.0" oder "V1.3.1.0" -> "1.4.0" oder "1.3.1.0")
            if (root.TryGetProperty("tag_name", out var tagElement))
            {
                var tagName = tagElement.GetString();
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Tag-Name aus GitHub: {tagName}");
                // Entferne sowohl kleine als auch große 'v' am Anfang
                versionInfo.LatestVersion = tagName?.TrimStart('v', 'V') ?? CurrentVersion;
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Bereinigter Version: {versionInfo.LatestVersion}");

                // Prüfe ob Update verfügbar ist
                var comparison = CompareVersions(versionInfo.LatestVersion, CurrentVersion);
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Versionsvergleich: {versionInfo.LatestVersion} vs {CurrentVersion} = {comparison}");

                if (comparison > 0)
                {
                    versionInfo.UpdateAvailable = true;
                }
            }
            else
            {
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Kein 'tag_name' Feld gefunden");
            }

            // Extrahiere Download-URL
            if (root.TryGetProperty("assets", out var assetsElement) && assetsElement.ValueKind == JsonValueKind.Array)
            {
                var assetCount = 0;
                foreach (var asset in assetsElement.EnumerateArray())
                {
                    assetCount++;
                    if (asset.TryGetProperty("browser_download_url", out var urlElement))
                    {
                        var url = urlElement.GetString();
                        System.Diagnostics.Debug.WriteLine($"[UpdateService] Asset {assetCount}: {url}");
                        // Suche nach .exe oder .zip Datei
                        if (url?.Contains(".exe") == true || url?.Contains(".zip") == true)
                        {
                            versionInfo.DownloadUrl = url;
                            System.Diagnostics.Debug.WriteLine($"[UpdateService] Download-URL gesetzt: {url}");
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
                var result = version1.CompareTo(version2);
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Version-Parse erfolgreich: {v1} -> {version1}");
                return result;
            }
            catch (FormatException ex)
            {
                System.Diagnostics.Debug.WriteLine($"[UpdateService] FEHLER beim Version-Parse: {v1} (Fehler: {ex.Message})");
                System.Diagnostics.Debug.WriteLine($"[UpdateService] Verwende default Vergleich (0 = gleich)");
                return 0;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[UpdateService] UNERWARTETER Fehler beim Versionsvergleich: {ex.Message}");
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
