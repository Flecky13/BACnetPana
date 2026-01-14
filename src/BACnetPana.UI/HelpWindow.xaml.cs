using System;
using System.Windows;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows.Navigation;
using BACnetPana.Core;

namespace BACnetPana.UI
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
            bool tsharkInstalled = BACnetPana.DataAccess.PcapParserFactory.IsTSharkInstalled();

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

        private void DownloadUpdateButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _updateService.OpenGitHubReleasePage();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fehler beim Öffnen der Release-Seite: {ex.Message}", "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
