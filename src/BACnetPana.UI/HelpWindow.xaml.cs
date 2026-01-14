using System;
using System.Windows;
using System.Diagnostics;

namespace BACnetPana.UI
{
    public partial class HelpWindow : Window
    {
        public HelpWindow()
        {
            InitializeComponent();
            InitializeHelpContent();
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

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
