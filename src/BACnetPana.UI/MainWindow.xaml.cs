using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using Microsoft.Win32;
using BACnetPana.Core.ViewModels;
using BACnetPana.Models;

namespace BACnetPana.UI
{
    public partial class MainWindow : Window
    {
        private MainViewModel _viewModel;
        private string _currentFilter = string.Empty;

        public MainWindow()
        {
            InitializeComponent();

            _viewModel = new MainViewModel();
            this.DataContext = _viewModel;

            // Bind collections and events
            PacketGrid.ItemsSource = _viewModel.Packets;
            LogList.ItemsSource = _viewModel.LogMessages;

            // Subscribe to selection changes
            PacketGrid.SelectionChanged += PacketGrid_SelectionChanged;

            // Subscribe to property changes to update UI automatically
            _viewModel.PropertyChanged += ViewModel_PropertyChanged;

            // Subscribe to LogMessages collection changes for auto-scrolling
            if (_viewModel.LogMessages is System.Collections.Specialized.INotifyCollectionChanged logCollection)
            {
                logCollection.CollectionChanged += (s, e) =>
                {
                    // Auto-scroll wenn CheckBox aktiviert ist
                    if (AutoScrollCheckBox.IsChecked == true && LogList.Items.Count > 0)
                    {
                        LogList.ScrollIntoView(LogList.Items[LogList.Items.Count - 1]);
                    }
                };
            }
        }

        private async void OpenFileButton_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = "PCAP/PCAPNG Files (*.pcap, *.pcapng, *.cap)|*.pcap;*.pcapng;*.cap|All Files (*.*)|*.*",
                Title = "PCAP/PCAPNG-Datei öffnen"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                var filePath = openFileDialog.FileName;

                // Erstelle ProgressWindow
                var progressWindow = new ProgressWindow
                {
                    Owner = this
                };

                // CancellationTokenSource für Abbruch
                var cancellationTokenSource = new System.Threading.CancellationTokenSource();

                // Progress-Callback
                Action<string, string, int> progressCallback = (phase, operation, percent) =>
                {
                    progressWindow.UpdateProgress(phase, operation, percent);

                    // Prüfe Abbruch
                    if (progressWindow.IsCancelled)
                    {
                        cancellationTokenSource.Cancel();
                    }
                };

                // Starte Import im Hintergrund
                var importTask = System.Threading.Tasks.Task.Run(async () =>
                {
                    try
                    {
                        var result = await _viewModel.OpenPcapFileWithProgress(filePath, progressCallback, cancellationTokenSource.Token);

                        if (result.HasValue)
                        {
                            // Update ObservableCollection auf UI-Thread
                            await Dispatcher.InvokeAsync(() =>
                            {
                                _viewModel.Packets.Clear();
                                foreach (var packet in result.Value.packets)
                                {
                                    _viewModel.Packets.Add(packet);
                                }
                                _viewModel.PacketStatistics = result.Value.statistics;
                            });
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        // Abbruch durch Benutzer
                        await Dispatcher.InvokeAsync(() =>
                        {
                            _viewModel.Packets.Clear();
                        });
                    }
                    catch (Exception ex)
                    {
                        await Dispatcher.InvokeAsync(() =>
                        {
                            MessageBox.Show($"Fehler beim Import:\n{ex.Message}", "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
                        });
                    }
                    finally
                    {
                        progressWindow.CloseWindow();
                    }
                });

                // Zeige ProgressWindow modal
                progressWindow.ShowDialog();
            }
        }

        private void WiresharkInfoButton_Click(object sender, RoutedEventArgs e)
        {
            // Öffne das neue Help-Fenster mit Tabs
            HelpWindow helpWindow = new HelpWindow
            {
                Owner = this
            };
            helpWindow.ShowDialog();
        }

        private void WiresharkInfoButton_Click_Old(object sender, RoutedEventArgs e)
        {
            bool tsharkInstalled = BACnetPana.DataAccess.PcapParserFactory.IsTSharkInstalled();

            string message;
            string title;
            MessageBoxImage icon;

            if (tsharkInstalled)
            {
                message = "✅ Wireshark/TShark ist installiert!\n\n" +
                         "Die Anwendung nutzt TShark für vollständige BACnet-Analyse:\n" +
                         "• Alle BACnet-Services (ReadProperty, WriteProperty, etc.)\n" +
                         "• Object Types und Instance Numbers\n" +
                         "• Property Identifiers\n" +
                         "• Vendor-Informationen\n\n" +
                         "Keine weiteren Schritte erforderlich.";
                title = "TShark Status";
                icon = MessageBoxImage.Information;
            }
            else
            {
                message = "⚠️ Wireshark/TShark ist NICHT installiert!\n\n" +
                         "Aktuell wird SharpPcap mit eingeschränkter BACnet-Unterstützung verwendet.\n\n" +
                         "Für vollständige BACnet-Analyse:\n" +
                         "1. Wireshark herunterladen und installieren\n" +
                         "   → https://www.wireshark.org/download.html\n\n" +
                         "2. TShark wird automatisch mit Wireshark installiert\n\n" +
                         "3. Anwendung neu starten\n\n" +
                         "Möchten Sie die Wireshark-Download-Seite öffnen?";
                title = "TShark nicht gefunden";
                icon = MessageBoxImage.Warning;

                var result = MessageBox.Show(message, title, MessageBoxButton.YesNo, icon);

                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "https://www.wireshark.org/download.html",
                            UseShellExecute = true
                        });
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Fehler beim Öffnen des Browsers: {ex.Message}",
                                      "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                return;
            }

            MessageBox.Show(message, title, MessageBoxButton.OK, icon);
        }

        private void AnalysisTcpButton_Click(object sender, RoutedEventArgs e)
        {
            // Hole die gefilterten Pakete aus der DataGrid
            var view = CollectionViewSource.GetDefaultView(_viewModel.Packets);
            var filteredPackets = new List<NetworkPacket>();

            foreach (var item in view)
            {
                if (item is NetworkPacket packet)
                {
                    filteredPackets.Add(packet);
                }
            }

            if (filteredPackets.Count == 0)
            {
                MessageBox.Show("Keine Pakete zur Analyse vorhanden.", "Keine Daten",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // Öffne TCP-Analyse-Fenster (bestehendes Fenster)
            var analysisWindow = new AnalysisWindow(filteredPackets, _currentFilter, _viewModel.BacnetDatabase);
            analysisWindow.Show();
        }

        private void AnalysisBacnetButton_Click(object sender, RoutedEventArgs e)
        {
            var view = CollectionViewSource.GetDefaultView(_viewModel.Packets);
            var filteredPackets = new List<NetworkPacket>();

            foreach (var item in view)
            {
                if (item is NetworkPacket packet)
                {
                    filteredPackets.Add(packet);
                }
            }

            if (filteredPackets.Count == 0)
            {
                MessageBox.Show("Keine Pakete zur Analyse vorhanden.", "Keine Daten",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // Öffne neues BACnet-Analyse-Fenster
            var bacnetWindow = new BACnetAnalysisWindow(filteredPackets, _currentFilter, _viewModel.BacnetDatabase);
            bacnetWindow.Show();
        }

        private void ClearLogButton_Click(object sender, RoutedEventArgs e)
        {
            _viewModel.LogMessages.Clear();
        }

        private void FilterByProtocolButton_Click(object sender, RoutedEventArgs e)
        {
            // Hole das ausgewählte TreeViewItem
            var selectedItem = HierarchicalProtocolTree.SelectedItem as ProtocolTreeNode;

            if (selectedItem != null)
            {
                ApplyFilter(selectedItem.Name);
            }
            else
            {
                MessageBox.Show("Bitte wählen Sie ein Protokoll aus der Liste aus.", "Kein Protokoll ausgewählt",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ClearFilterButton_Click(object sender, RoutedEventArgs e)
        {
            ApplyFilter("");
        }

        private void ApplyFilter(string filterText)
        {
            if (string.IsNullOrWhiteSpace(filterText))
            {
                _currentFilter = string.Empty;
                // Kein Filter - zeige alle Pakete
                var view = CollectionViewSource.GetDefaultView(_viewModel.Packets);
                view.Filter = null;
                _viewModel.AddUiLog($"Filter entfernt - {_viewModel.Packets.Count} Pakete angezeigt");

                // Update UI - kein Filter aktiv
                ProtocolHeaderTextBlock.Text = "Protokolle (Hierarchisch)";
                ProtocolHeaderTextBlock.Foreground = System.Windows.Media.Brushes.Black;

                // BACnet-Button sichtbar, wenn keine Filterung oder Filter BACnet enthält
                if (AnalysisBacnetButton != null)
                    AnalysisBacnetButton.Visibility = Visibility.Visible;
            }
            else
            {
                _currentFilter = filterText;
                var filter = filterText.ToLower();

                // Filtere Pakete
                var view = CollectionViewSource.GetDefaultView(_viewModel.Packets);
                view.Filter = obj =>
                {
                    if (obj is NetworkPacket packet)
                    {
                        // Optimierte Filter-Logik mit unterschiedlichen Match-Strategien

                        // 1. Prüfe ApplicationProtocol (EXAKTER Match - nicht Substring!)
                        // Damit HTTP und HTTPS getrennt sind
                        if (!string.IsNullOrEmpty(packet.ApplicationProtocol) &&
                            packet.ApplicationProtocol.Equals(filter, StringComparison.OrdinalIgnoreCase))
                            return true;

                        // 2. Prüfe Protocol (EXAKTER Match - UDP, TCP, etc.)
                        if (!string.IsNullOrEmpty(packet.Protocol) &&
                            packet.Protocol.Equals(filter, StringComparison.OrdinalIgnoreCase))
                            return true;

                        // 3. Prüfe IPs (Substring-Match ist hier sinnvoll)
                        if (!string.IsNullOrEmpty(packet.SourceIp) &&
                            packet.SourceIp.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)
                            return true;

                        if (!string.IsNullOrEmpty(packet.DestinationIp) &&
                            packet.DestinationIp.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)
                            return true;

                        // 4. Prüfe Ports (numerisch)
                        if (packet.SourcePort > 0 && packet.SourcePort.ToString().Contains(filter))
                            return true;

                        if (packet.DestinationPort > 0 && packet.DestinationPort.ToString().Contains(filter))
                            return true;
                    }
                    return false;
                };

                // Log ohne die gefilterte Anzahl zu berechnen (Performance!)
                _viewModel.AddUiLog($"Filter '{filterText}' angewendet");

                // Update UI - Filter aktiv
                ProtocolHeaderTextBlock.Text = "Protokolle (Hierarchisch) (gefiltert)";
                ProtocolHeaderTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0, 120, 212)); // #0078D4 Blau

                // BACnet-Button nur sichtbar, wenn Filter BACnet-relevant ist
                // UDP enthält auch BACnet (Ports 47808-47823)!
                bool isBacnetFilter = filterText.Equals("bacnet", StringComparison.OrdinalIgnoreCase) ||
                                     filterText.Equals("bac", StringComparison.OrdinalIgnoreCase) ||
                                     filterText.Equals("udp", StringComparison.OrdinalIgnoreCase) ||
                                     (int.TryParse(filterText, out int port) && port >= 47808 && port <= 47823);

                if (AnalysisBacnetButton != null)
                    AnalysisBacnetButton.Visibility = isBacnetFilter ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        private void ViewModel_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(MainViewModel.PacketStatistics))
            {
                // Update statistics display when PacketStatistics changes
                UpdateStatisticsDisplay();
            }
        }

        private void PacketGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PacketGrid.SelectedItem is NetworkPacket packet)
            {
                _viewModel.SelectedPacket = packet;
                UpdatePacketDetails(packet);
                UpdateStatisticsDisplay();
            }
        }

        private void PacketGrid_MouseButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            // Handle packet selection
        }

        private void UpdatePacketDetails(NetworkPacket packet)
        {
            PacketDetailsTree.Items.Clear();

            // General Information
            var generalItem = new TreeViewItem { Header = "Allgemein" };
            generalItem.Items.Add(new TreeViewItem { Header = $"Paket Nr.: {packet.PacketNumber}" });
            generalItem.Items.Add(new TreeViewItem { Header = $"Zeit: {packet.Timestamp:HH:mm:ss.fff}" });
            generalItem.Items.Add(new TreeViewItem { Header = $"Größe: {packet.PacketLength} Bytes" });
            PacketDetailsTree.Items.Add(generalItem);

            // Ethernet
            if (!string.IsNullOrEmpty(packet.SourceMac))
            {
                var ethernetItem = new TreeViewItem { Header = "Ethernet" };
                ethernetItem.Items.Add(new TreeViewItem { Header = $"Quell-MAC: {packet.SourceMac}" });
                ethernetItem.Items.Add(new TreeViewItem { Header = $"Ziel-MAC: {packet.DestinationMac}" });
                ethernetItem.Items.Add(new TreeViewItem { Header = $"Typ: {packet.EthernetType}" });
                PacketDetailsTree.Items.Add(ethernetItem);
            }

            // IP
            if (!string.IsNullOrEmpty(packet.SourceIp))
            {
                var ipItem = new TreeViewItem { Header = "IP" };
                ipItem.Items.Add(new TreeViewItem { Header = $"Quell-IP: {packet.SourceIp}" });
                ipItem.Items.Add(new TreeViewItem { Header = $"Ziel-IP: {packet.DestinationIp}" });
                ipItem.Items.Add(new TreeViewItem { Header = $"Protokoll: {packet.Protocol}" });
                ipItem.Items.Add(new TreeViewItem { Header = $"TTL: {packet.Ttl}" });
                PacketDetailsTree.Items.Add(ipItem);
            }

            // Transport
            if (packet.SourcePort > 0 || packet.DestinationPort > 0)
            {
                var transportItem = new TreeViewItem { Header = "Transport" };
                if (packet.SourcePort > 0)
                    transportItem.Items.Add(new TreeViewItem { Header = $"Quell-Port: {packet.SourcePort}" });
                if (packet.DestinationPort > 0)
                    transportItem.Items.Add(new TreeViewItem { Header = $"Ziel-Port: {packet.DestinationPort}" });

                foreach (var detail in packet.Details)
                {
                    transportItem.Items.Add(new TreeViewItem { Header = $"{detail.Key}: {detail.Value}" });
                }

                PacketDetailsTree.Items.Add(transportItem);
            }
        }

        private void UpdateStatisticsDisplay()
        {
            if (_viewModel.PacketStatistics == null)
                return;

            TotalPacketsLabel.Text = _viewModel.PacketStatistics.TotalPackets.ToString();
            TotalBytesLabel.Text = FormatBytes(_viewModel.PacketStatistics.TotalBytes);
            DurationLabel.Text = $"{_viewModel.PacketStatistics.GetDurationSeconds():F2} s";
            ThroughputLabel.Text = $"{_viewModel.PacketStatistics.GetMegabitsPerSecond():F2} Mbps";

            // Update protocol list
            HierarchicalProtocolTree.Items.Clear();

            // Gruppiere nach Transport-Protokoll
            var transportGroups = _viewModel.PacketStatistics.HierarchicalProtocolCount
                .GroupBy(p => p.Key.Contains("/") ? p.Key.Split('/')[0] : p.Key)
                .OrderByDescending(g => g.Sum(x => x.Value));

            foreach (var transportGroup in transportGroups)
            {
                var transportProtocol = transportGroup.Key;
                var totalCount = transportGroup.Sum(x => x.Value);

                // Erstelle Hauptknoten (z.B. "UDP", "TCP")
                var rootNode = new ProtocolTreeNode
                {
                    Name = transportProtocol,
                    Count = totalCount,
                    FontWeight = "Bold",
                    Children = new System.Collections.ObjectModel.ObservableCollection<ProtocolTreeNode>()
                };

                // Füge alle erkannten Unterprotokolle einzeln hinzu
                var subProtocols = transportGroup
                    .Where(p => p.Key.Contains("/"))
                    .Select(p => new { AppProtocol = p.Key.Split('/')[1], Count = p.Value })
                    .OrderByDescending(x => x.Count);

                foreach (var sub in subProtocols)
                {
                    rootNode.Children.Add(new ProtocolTreeNode
                    {
                        Name = sub.AppProtocol,
                        Count = sub.Count,
                        FontWeight = "Normal"
                    });
                }

                // Pakete ohne erkanntes Application-Protokoll
                // Diese sind normale UDP/TCP-Pakete ohne identifizierbare höhere Protokolle
                var packetsWithoutAppProtocol = transportGroup
                    .Where(p => !p.Key.Contains("/") && p.Key == transportProtocol)
                    .Sum(x => x.Value);

                // Zeige diese nur an, wenn es relevante Mengen sind
                // Überspringe Layer-2/3-Protokolle wie ARP, ICMP, IGMP
                bool isLayer34Protocol = transportProtocol.Equals("Arp", StringComparison.OrdinalIgnoreCase) ||
                                        transportProtocol.Equals("Igmp", StringComparison.OrdinalIgnoreCase) ||
                                        transportProtocol.Equals("Icmp", StringComparison.OrdinalIgnoreCase) ||
                                        transportProtocol.Equals("ICMP", StringComparison.OrdinalIgnoreCase);

                if (packetsWithoutAppProtocol > 0 && !isLayer34Protocol)
                {
                    var genericNode = new ProtocolTreeNode
                    {
                        Name = $"{transportProtocol} (ohne App-Protokoll)",
                        Count = packetsWithoutAppProtocol,
                        FontWeight = "Normal",
                        Children = new System.Collections.ObjectModel.ObservableCollection<ProtocolTreeNode>()
                    };

                    // Zeige Top-Ports dieser Pakete
                    var genericPackets = _viewModel.Packets
                        .Where(p => !string.IsNullOrEmpty(p.Protocol) &&
                                    p.Protocol.Equals(transportProtocol, StringComparison.OrdinalIgnoreCase) &&
                                    string.IsNullOrEmpty(p.ApplicationProtocol))
                        .ToList();

                    if (genericPackets.Any())
                    {
                        var portCounts = new Dictionary<int, int>();

                        foreach (var packet in genericPackets)
                        {
                            // Zähle Destination-Port (häufiger relevant als Source)
                            int port = packet.DestinationPort > 0 ? packet.DestinationPort : packet.SourcePort;

                            if (port > 0)
                            {
                                if (!portCounts.ContainsKey(port))
                                    portCounts[port] = 0;
                                portCounts[port]++;
                            }
                        }

                        var topPorts = portCounts
                            .OrderByDescending(kvp => kvp.Value)
                            .Take(20);

                        foreach (var portEntry in topPorts)
                        {
                            genericNode.Children.Add(new ProtocolTreeNode
                            {
                                Name = $"Port {portEntry.Key}",
                                Count = portEntry.Value,
                                FontWeight = "Normal"
                            });
                        }
                    }

                    rootNode.Children.Add(genericNode);
                }

                HierarchicalProtocolTree.Items.Add(rootNode);
            }

            // Update top IPs
            TopIpsList.Items.Clear();
            foreach (var ip in _viewModel.PacketStatistics.IpSourceCount.OrderByDescending(p => p.Value).Take(10))
            {
                TopIpsList.Items.Add($"{ip.Key} ({ip.Value} Pakete)");
            }
        }

        private string FormatBytes(long bytes)
        {
            if (bytes >= 1024 * 1024 * 1024)
                return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
            if (bytes >= 1024 * 1024)
                return $"{bytes / (1024.0 * 1024):F2} MB";
            if (bytes >= 1024)
                return $"{bytes / 1024.0:F2} KB";
            return $"{bytes} B";
        }
    }

    /// <summary>
    /// TreeView-Node für hierarchische Protokoll-Darstellung
    /// </summary>
    public class ProtocolTreeNode
    {
        public string Name { get; set; } = "";
        public int Count { get; set; }
        public string FontWeight { get; set; } = "Normal";
        public System.Collections.ObjectModel.ObservableCollection<ProtocolTreeNode>? Children { get; set; }
    }
}
