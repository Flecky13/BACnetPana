using System;
using System.Windows;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows.Navigation;
using bacneTPana.Core;

namespace bacneTPana.UI
{
    public partial class HelpWindow : Window
    {
        private UpdateService _updateService;

        public HelpWindow()
        {
            InitializeComponent();
            _updateService = new UpdateService();
            InitializeHelpContent();
            InitializeInfoTab();
        }

        private void InitializeHelpContent()
        {
            // Prüfe TShark-Status und aktualisiere Text
            bool tsharkInstalled = bacneTPana.DataAccess.PcapParserFactory.IsTSharkInstalled();

            if (tsharkInstalled)
            {
                TSharkStatusText.Text = "✅ Wireshark/TShark ist installiert!\n\nDie Anwendung nutzt TShark für vollständige BACnet-Analyse. Keine weiteren Schritte erforderlich.";
            }
            else
            {
                TSharkStatusText.Text = "⚠️ Wireshark/TShark ist NICHT installiert!\n\nAktuell wird SharpPcap mit eingeschränkter BACnet-Unterstützung verwendet.\n\nBitte folgen Sie der Anleitung unten zur Installation.";
            }

            // Hyperlink-Handler
            WiresharkLink.RequestNavigate += (sender, e) =>
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = e.Uri.AbsoluteUri,
                        UseShellExecute = true
                    };
                    Process.Start(psi);
                    e.Handled = true;
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Konnte Link nicht öffnen: {ex.Message}", "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            };
        }

        private async void InitializeInfoTab()
        {
            // Zeige Versions-Info
            var appInfo = _updateService.GetApplicationInfo();
            VersionTextBlock.Text = $"Version: {appInfo.CurrentVersion}";
            AuthorTextBlock.Text = $"Entwickler: {appInfo.Author}";

            // Repository-/Support-Link öffnen
            RepositoryLink.RequestNavigate += OpenLink;
            SupportLink.RequestNavigate += OpenLink;

            // Starte Update-Check asynchron
            CheckForUpdatesButton.Click += async (s, e) => await CheckForUpdatesAsync();

            // Auto-Check beim Laden
            await CheckForUpdatesAsync();
        }

        private void OpenLink(object? sender, RequestNavigateEventArgs e)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = e.Uri.AbsoluteUri,
                    UseShellExecute = true
                };
                Process.Start(psi);
                e.Handled = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Konnte Link nicht öffnen: {ex.Message}", "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task CheckForUpdatesAsync()
        {
            try
            {
                UpdateStatusTextBlock.Text = "🔄 Prüfe auf Updates...";
                UpdateStatusTextBlock.Foreground = System.Windows.Media.Brushes.Gray;

                var versionInfo = await _updateService.CheckForUpdatesAsync();

                if (versionInfo.UpdateAvailable)
                {
                    UpdateStatusTextBlock.Text = $"✅ Update verfügbar! Neue Version: {versionInfo.LatestVersion}";
                    UpdateStatusTextBlock.Foreground = System.Windows.Media.Brushes.Green;
                    DownloadUpdateButton.Visibility = Visibility.Visible;

                    if (!string.IsNullOrEmpty(versionInfo.ReleaseNotes))
                    {
                        ReleaseNotesTextBlock.Text = versionInfo.ReleaseNotes;
                    }
                }
                else
                {
                    UpdateStatusTextBlock.Text = $"✅ Sie verwenden die neueste Version ({versionInfo.CurrentVersion})";
                    UpdateStatusTextBlock.Foreground = System.Windows.Media.Brushes.DarkGreen;
                    DownloadUpdateButton.Visibility = Visibility.Collapsed;
                }
            }
            catch (Exception ex)
            {
                UpdateStatusTextBlock.Text = $"❌ Fehler beim Update-Check: {ex.Message}";
                UpdateStatusTextBlock.Foreground = System.Windows.Media.Brushes.Red;
            }
        }

        private async void DownloadUpdateButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                DownloadUpdateButton.IsEnabled = false;
                UpdateStatusTextBlock.Text = "⏳ Lade Setup herunter und starte Installation...";
                UpdateStatusTextBlock.Foreground = System.Windows.Media.Brushes.Gray;

                // Erstelle Pfad für Setup-Datei
                string tempPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "bacneTPana_Setup.exe");

                // Ermittle Download-URL - müssen von der UpdateService abrufen
                var versionInfo = await _updateService.CheckForUpdatesAsync();

                if (string.IsNullOrEmpty(versionInfo.DownloadUrl))
                {
                    MessageBox.Show("Keine Download-URL für die Update-Datei gefunden.", "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
                    DownloadUpdateButton.IsEnabled = true;
                    return;
                }

                // Download der Setup-Datei
                bool downloadSuccess = await _updateService.DownloadUpdateAsync(versionInfo.DownloadUrl, tempPath);

                if (!downloadSuccess)
                {
                    MessageBox.Show("Fehler beim Herunterladen der Setup-Datei.", "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
                    DownloadUpdateButton.IsEnabled = true;
                    return;
                }

                UpdateStatusTextBlock.Text = "✅ Setup heruntergeladen. Starte Installation...";
                UpdateStatusTextBlock.Foreground = System.Windows.Media.Brushes.Green;

                // Starte die Setup-Datei
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = tempPath,
                    UseShellExecute = true
                };
                Process.Start(psi);

                // Warte kurz, dann beende die Anwendung
                await Task.Delay(1000);
                Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fehler beim Update-Prozess: {ex.Message}", "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
                DownloadUpdateButton.IsEnabled = true;
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
