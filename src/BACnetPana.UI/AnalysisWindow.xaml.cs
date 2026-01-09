using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using BACnetPana.Models;
using OxyPlot;
using OxyPlot.Series;
using OxyPlot.Axes;

namespace BACnetPana.UI
{
    public partial class AnalysisWindow : Window
    {
        private List<NetworkPacket> _packets;
        private DateTime _minTime;
        private DateTime _maxTime;
        private double _totalDuration;
        private readonly PlotController _noWheelController = new PlotController();
        private readonly string _activeFilter;
        private DispatcherTimer? _debounceTimer;
        private BACnetDatabase _bacnetDb;

        public AnalysisWindow(List<NetworkPacket> packets, string activeFilter, BACnetDatabase? bacnetDatabase = null)
        {
            InitializeComponent();
            _packets = packets ?? new List<NetworkPacket>();
            _activeFilter = activeFilter ?? string.Empty;
            _bacnetDb = bacnetDatabase ?? new BACnetDatabase();

            // Debug: Log BACnet-Datenbank Status
            System.Diagnostics.Debug.WriteLine($"AnalysisWindow: BACnetDatabase empfangen - IpToInstance: {_bacnetDb.IpToInstance?.Count ?? 0}, IpToDeviceName: {_bacnetDb.IpToDeviceName?.Count ?? 0}");

            ConfigurePlotController();

            UpdateTitleWithFilter();

            LoadAnalysis();
        }

        private void ConfigurePlotController()
        {
            _noWheelController.UnbindMouseWheel();
        }

        private void LoadAnalysis()
        {
            // BACnet-Datenbasis wurde bereits beim Einlesen der PCAP aufgebaut und geloggt

            // Berechne Zusammenfassung
            var packetCount = _packets.Count;
            var totalSize = _packets.Sum(p => p.PacketLength);
            var uniqueProtocols = _packets.Select(p => p.DisplayProtocol).Distinct().Count();

            // Zeitspanne
            var timeSpan = "0 s";
            if (_packets.Count >= 2)
            {
                _minTime = _packets.Min(p => p.Timestamp);
                _maxTime = _packets.Max(p => p.Timestamp);
                var duration = _maxTime - _minTime;
                _totalDuration = duration.TotalSeconds;
                timeSpan = $"{_totalDuration:F2} s";
            }
            else if (_packets.Count == 1)
            {
                _minTime = _packets[0].Timestamp;
                _maxTime = _packets[0].Timestamp;
                _totalDuration = 0;
            }

            // Absolute Start/Endzeiten immer aus Gesamtdaten anzeigen
            if (packetCount > 0)
            {
                if (SummaryStartDateTimeLabel != null)
                    SummaryStartDateTimeLabel.Text = FormatDateTimeTwoLines(_minTime);
                if (SummaryEndDateTimeLabel != null)
                    SummaryEndDateTimeLabel.Text = FormatDateTimeTwoLines(_maxTime);
            }
            else
            {
                if (SummaryStartDateTimeLabel != null)
                    SummaryStartDateTimeLabel.Text = "—";
                if (SummaryEndDateTimeLabel != null)
                    SummaryEndDateTimeLabel.Text = "—";
            }

            // Update UI
            PacketCountLabel.Text = packetCount.ToString();
            TotalSizeLabel.Text = FormatBytes(totalSize);
            TimeSpanLabel.Text = timeSpan;
            ProtocolCountLabel.Text = uniqueProtocols.ToString();

            // Initialisiere die Slider
            if (StartTimeSlider != null && EndTimeSlider != null)
            {
                StartTimeSlider.Maximum = _totalDuration;
                EndTimeSlider.Maximum = _totalDuration;
                StartTimeSlider.Value = 0;
                EndTimeSlider.Value = _totalDuration;

                // Erstelle das Diagramm
                UpdateChart();
            }
        }

        private void UpdateChart()
        {
            // Prüfe, ob die Pakete vorhanden sind
            if (_packets == null || _packets.Count == 0)
                return;

            // Prüfe, ob die Slider initialisiert sind
            if (StartTimeSlider == null || EndTimeSlider == null)
                return;

            // Hole die ausgewählte Zeitspanne
            var startOffset = StartTimeSlider.Value;
            var endOffset = EndTimeSlider.Value;

            // Validierung: Start muss vor Ende liegen
            if (startOffset >= endOffset)
            {
                return;
            }

            var startTime = _minTime.AddSeconds(startOffset);
            var endTime = _minTime.AddSeconds(endOffset);

            // Filtere Pakete nach Zeitbereich
            var filteredPackets = _packets
                .Where(p => p.Timestamp >= startTime && p.Timestamp <= endTime)
                .OrderBy(p => p.Timestamp)
                .ToList();

            // Berechne Packets/sec
            var packetsPerSecond = CalculatePacketsPerSecond(filteredPackets, startTime, endTime);

            // Aktualisiere Broadcast-Ansicht
            UpdateBroadcastSection(filteredPackets);

            // Erstelle das Plot-Modell
            var plotModel = new PlotModel
            {
                Title = "Pakete pro Sekunde",
                Background = OxyColors.White
            };

            // Konfiguriere X-Achse (Zeit in Sekunden seit Start)
            var xAxis = new LinearAxis
            {
                Position = AxisPosition.Bottom,
                Title = "Zeit (s)",
                MajorGridlineStyle = LineStyle.Solid,
                MinorGridlineStyle = LineStyle.Dot,
                MajorGridlineColor = OxyColor.FromRgb(220, 220, 220),
                MinorGridlineColor = OxyColor.FromRgb(240, 240, 240),
                Minimum = 0,
                Maximum = Math.Max(0.0001, (endTime - startTime).TotalSeconds),
                IsPanEnabled = false,
                IsZoomEnabled = false
            };
            plotModel.Axes.Add(xAxis);

            // Konfiguriere Y-Achse (Pakete/Sekunde)
            var yAxis = new LinearAxis
            {
                Position = AxisPosition.Left,
                Title = "Pakete/s",
                MajorGridlineStyle = LineStyle.Solid,
                MinorGridlineStyle = LineStyle.Dot,
                MajorGridlineColor = OxyColor.FromRgb(220, 220, 220),
                MinorGridlineColor = OxyColor.FromRgb(240, 240, 240),
                Minimum = 0,
                AbsoluteMinimum = 0,
                IsPanEnabled = false,
                IsZoomEnabled = false
            };
            plotModel.Axes.Add(yAxis);

            // Erstelle die Linienserie
            var lineSeries = new LineSeries
            {
                Title = "Pakete/s",
                Color = OxyColor.FromRgb(0, 120, 212),
                StrokeThickness = 2,
                MarkerType = MarkerType.None,
                CanTrackerInterpolatePoints = false
            };

            lineSeries.Points.AddRange(packetsPerSecond);

            plotModel.Series.Add(lineSeries);

            // Setze das Plot-Modell
            if (TimeChart != null)
            {
                TimeChart.Model = plotModel;
                TimeChart.Controller = _noWheelController;
            }

            // Update Labels
            if (StartTimeLabel != null)
                StartTimeLabel.Text = $"{startOffset:F2} s";
            if (EndTimeLabel != null)
                EndTimeLabel.Text = $"{endOffset:F2} s";
            if (DurationLabel != null)
                DurationLabel.Text = $"Anzeigedauer: {(endOffset - startOffset):F2} s";

            var startAbs = startTime.ToString("yyyy-MM-dd HH:mm:ss.fff");
            var endAbs = endTime.ToString("yyyy-MM-dd HH:mm:ss.fff");
            if (StartDateTimeLabel != null)
                StartDateTimeLabel.Text = FormatDateTimeTwoLines(startTime);
            if (EndDateTimeLabel != null)
                EndDateTimeLabel.Text = FormatDateTimeTwoLines(endTime);
        }

        private void UpdateTitleWithFilter()
        {
            var suffix = string.IsNullOrWhiteSpace(_activeFilter)
                ? "(kein Filter)"
                : $"(Filter: {_activeFilter})";
            if (AnalysisTitleTextBlock != null)
            {
                AnalysisTitleTextBlock.Text = $"Analyse der gefilterten Pakete {suffix}";
            }
        }

        private static string FormatDateTimeTwoLines(DateTime value)
        {
            // Zweizeilig: Datum oben, Zeit unten
            return value.ToString("yyyy-MM-dd\nHH:mm:ss.fff");
        }

        private void UpdateBroadcastSection(List<NetworkPacket> filteredPackets)
        {
            // First check if there are any BACnet packets
            var bacnetPackets = filteredPackets.Where(p =>
                (p.ApplicationProtocol?.ToUpper() == "BACNET") ||
                (p.DestinationPort >= 47808 && p.DestinationPort <= 47823) ||
                (p.SourcePort >= 47808 && p.SourcePort <= 47823)).ToList();

            bool hasBACnetPackets = bacnetPackets.Count > 0;

            // TCP Analysis
            UpdateTcpAnalysis(filteredPackets);

            // BACnet Analysis (only if BACnet packets exist)
            if (hasBACnetPackets)
            {
                // Show the entire BACnet section
                if (BACnetSectionBorder != null)
                    BACnetSectionBorder.Visibility = Visibility.Visible;

                UpdateBACnetDatabaseStats();
                UpdateBACnetAnalysis(filteredPackets);
                UpdateBACnetServicesAnalysis(filteredPackets);
                UpdateBACnetReadPropertiesAnalysis(filteredPackets);
            }
            else
            {
                // Hide the entire BACnet section when no BACnet packets
                if (BACnetSectionBorder != null)
                    BACnetSectionBorder.Visibility = Visibility.Collapsed;
            }

            var broadcastPackets = filteredPackets
                .Where(IsBroadcast)
                .ToList();

            var totalBroadcasts = broadcastPackets.Count;
            if (BroadcastCountLabel != null)
            {
                BroadcastCountLabel.Text = $"Broadcasts: {totalBroadcasts}";
            }

            // Top-Absender aggregieren
            var allSources = broadcastPackets
                .GroupBy(p => string.IsNullOrWhiteSpace(p.SourceIp) ? "Unbekannt" : p.SourceIp)
                .Select(g => new { Source = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .ToList();

            var senderCount = allSources.Count;
            if (BroadcastCountLabel != null)
            {
                BroadcastCountLabel.Text = $"Broadcasts: {totalBroadcasts} | Sender: {senderCount}";
            }

            // Chart: Top 10 (absteigend)
            var topSources = allSources.Take(10).ToList();

            var barHeight = 22; // px pro Balken, schmaler
            var desiredHeight = Math.Max(10, topSources.Count) * barHeight;

            var broadcastModel = new PlotModel
            {
                Title = "Broadcast-Absender",
                Background = OxyColors.White
            };

            var categoryAxis = new CategoryAxis
            {
                Position = AxisPosition.Left,
                ItemsSource = topSources,
                LabelField = "Source",
                GapWidth = 0.5
            };
            broadcastModel.Axes.Add(categoryAxis);

            var valueAxis = new LinearAxis
            {
                Position = AxisPosition.Bottom,
                Title = "Broadcasts",
                MinimumPadding = 0,
                AbsoluteMinimum = 0,
                MajorGridlineStyle = LineStyle.Solid,
                MinorGridlineStyle = LineStyle.Dot,
                MajorGridlineColor = OxyColor.FromRgb(220, 220, 220),
                MinorGridlineColor = OxyColor.FromRgb(240, 240, 240)
            };
            broadcastModel.Axes.Add(valueAxis);

            // Höhe setzen, damit ScrollViewer ggf. scrollt
            if (BroadcastChart != null)
            {
                BroadcastChart.Height = desiredHeight;
            }

            var series = new BarSeries
            {
                ItemsSource = topSources,
                ValueField = "Count",
                FillColor = OxyColor.FromRgb(0, 120, 212),
                StrokeColor = OxyColor.FromRgb(0, 90, 160),
                StrokeThickness = 1,
                BarWidth = 0.6,
                LabelFormatString = "{0}",
                LabelPlacement = LabelPlacement.Inside,
                LabelMargin = 2,
                TextColor = OxyColors.White
            };
            broadcastModel.Series.Add(series);

            if (BroadcastChart != null)
            {
                BroadcastChart.Model = broadcastModel;
                BroadcastChart.Controller = _noWheelController;
            }
        }

        private bool IsBroadcast(NetworkPacket packet)
        {
            var dest = packet.DestinationIp;
            if (string.IsNullOrWhiteSpace(dest))
                return false;

            return dest == "255.255.255.255" || dest.EndsWith(".255");
        }

        private void UpdateTcpAnalysis(List<NetworkPacket> filteredPackets)
        {
            // Zähle TCP-Pakete und analysiere TCP-Probleme
            var tcpPackets = filteredPackets.Where(p => p.Protocol?.ToUpper() == "TCP").ToList();

            if (tcpPackets.Count == 0)
            {
                // Keine TCP-Pakete -> Bereich ausblenden
                if (TcpAnalysisBorder != null)
                    TcpAnalysisBorder.Visibility = Visibility.Collapsed;
                return;
            }

            // TCP-Pakete vorhanden -> Bereich anzeigen
            if (TcpAnalysisBorder != null)
                TcpAnalysisBorder.Visibility = Visibility.Visible;

            // Zähle TCP-Probleme aus Details dictionary
            var retransmissionCount = 0;
            var duplicateAckCount = 0;
            var fastRetransmissionCount = 0;
            var resetCount = 0;
            var icmpUnreachableCount = 0;
            var lostSegmentCount = 0;
            var outOfOrderCount = 0;
            var windowSizeZeroCount = 0;
            var keepAliveCount = 0;

            foreach (var packet in tcpPackets)
            {
                if (packet.Details != null)
                {
                    foreach (var detail in packet.Details)
                    {
                        var key = detail.Key?.ToLower() ?? "";
                        var value = detail.Value?.ToLower() ?? "";

                        if (key.Contains("retransmission") || value.Contains("retransmission"))
                            retransmissionCount++;
                        else if (key.Contains("duplicate") && key.Contains("ack") || value.Contains("duplicate") && value.Contains("ack"))
                            duplicateAckCount++;
                        else if (key.Contains("fast") && key.Contains("retransmission") || value.Contains("fast") && value.Contains("retransmission"))
                            fastRetransmissionCount++;
                        else if (key.Contains("reset") || value.Contains("reset"))
                            resetCount++;
                        else if (key.Contains("lost_segment") || value.Contains("lost segment") || key.Contains("tcp lost segment") || value.Contains("tcp lost segment"))
                            lostSegmentCount++;
                        else if (key.Contains("out_of_order") || value.Contains("out of order") || key.Contains("tcp out-of-order") || value.Contains("tcp out of order"))
                            outOfOrderCount++;
                        else if (key.Contains("zero_window") || value.Contains("zero window") || key.Contains("window size") && value.Contains("0"))
                            windowSizeZeroCount++;
                        else if (key.Contains("keep_alive") || value.Contains("keep alive") || key.Contains("keepalive") || value.Contains("keepalive"))
                            keepAliveCount++;
                    }
                }
            }

            // ICMP Destination Unreachable innerhalb der Zeitspanne erfassen
            var icmpPackets = filteredPackets.Where(p => p.Protocol?.ToUpper() == "ICMP" && p.Details != null).ToList();
            foreach (var ipkt in icmpPackets)
            {
                if (ipkt.Details.TryGetValue("ICMP Type", out var t))
                {
                    var lower = (t ?? string.Empty).ToLowerInvariant();
                    if (lower.Contains("unreachable") || lower.Contains("destination unreachable") || lower.Contains("type=3") || lower == "3")
                        icmpUnreachableCount++;
                }
            }

            // Update Labels
            if (TcpRetransmissionLabel != null)
                TcpRetransmissionLabel.Text = retransmissionCount.ToString();
            if (TcpDuplicateAckLabel != null)
                TcpDuplicateAckLabel.Text = duplicateAckCount.ToString();
            if (TcpFastRetransmissionLabel != null)
                TcpFastRetransmissionLabel.Text = fastRetransmissionCount.ToString();
            if (TcpResetLabel != null)
                TcpResetLabel.Text = resetCount.ToString();
            if (TcpLostSegmentLabel != null)
                TcpLostSegmentLabel.Text = lostSegmentCount.ToString();
            if (TcpOutOfOrderLabel != null)
                TcpOutOfOrderLabel.Text = outOfOrderCount.ToString();
            if (TcpWindowSizeZeroLabel != null)
                TcpWindowSizeZeroLabel.Text = windowSizeZeroCount.ToString();
            if (TcpKeepAliveLabel != null)
                TcpKeepAliveLabel.Text = keepAliveCount.ToString();
            if (TcpIcmpUnreachableLabel != null)
                TcpIcmpUnreachableLabel.Text = icmpUnreachableCount.ToString();

            // Ampel-Farben basierend auf Prozentanteil
            double totalTcp = Math.Max(1, tcpPackets.Count);
            SetAmpel(TcpRetransmissionIndicator, retransmissionCount * 100.0 / totalTcp);
            SetAmpel(TcpDuplicateAckIndicator, duplicateAckCount * 100.0 / totalTcp);
            SetAmpel(TcpFastRetransmissionIndicator, fastRetransmissionCount * 100.0 / totalTcp);
            SetAmpel(TcpResetIndicator, resetCount * 100.0 / totalTcp);
            SetAmpel(TcpLostSegmentIndicator, lostSegmentCount * 100.0 / totalTcp);
            SetAmpel(TcpOutOfOrderIndicator, outOfOrderCount * 100.0 / totalTcp);
            SetAmpel(TcpWindowSizeZeroIndicator, windowSizeZeroCount * 100.0 / totalTcp);
            SetAmpel(TcpKeepAliveIndicator, keepAliveCount * 100.0 / totalTcp);
            SetAmpel(TcpIcmpUnreachableIndicator, icmpUnreachableCount * 100.0 / totalTcp);

            // Gesamtverlust: Summe aller TCP-Fehler
            var lossEventsTotal = retransmissionCount + duplicateAckCount + fastRetransmissionCount + icmpUnreachableCount + resetCount + lostSegmentCount + outOfOrderCount + windowSizeZeroCount + keepAliveCount;
            var lossPercent = lossEventsTotal * 100.0 / totalTcp;
            if (TcpLossOverallLabel != null)
                TcpLossOverallLabel.Text = $"{lossEventsTotal} ({lossPercent:F2} %)";
            SetAmpel(TcpLossOverallIndicator, lossPercent);
        }

        private void SetAmpel(System.Windows.Shapes.Ellipse? indicator, double percent)
        {
            if (indicator == null)
                return;
            var brush = GetAmpelBrush(percent);
            indicator.Fill = brush;
        }

        private Brush GetAmpelBrush(double percent)
        {
            // 🟢 Grün < 1%, 🟡 Gelb 1–3%, 🔴 Rot > 3%
            if (percent < 1.0) return new SolidColorBrush(Color.FromRgb(0x4C, 0xAF, 0x50)); // Grün
            if (percent <= 3.0) return new SolidColorBrush(Color.FromRgb(0xFF, 0xC1, 0x07)); // Gelb
            return new SolidColorBrush(Color.FromRgb(0xD1, 0x34, 0x38)); // Rot
        }

        private void UpdateBACnetAnalysis(List<NetworkPacket> filteredPackets)
        {
            // Erkenne BACnet-Pakete (ApplicationProtocol == "BACnet" oder Port 47808-47823)
            var bacnetPackets = filteredPackets.Where(p =>
                (p.ApplicationProtocol?.ToUpper() == "BACNET") ||
                (p.DestinationPort >= 47808 && p.DestinationPort <= 47823) ||
                (p.SourcePort >= 47808 && p.SourcePort <= 47823)).ToList();

            if (bacnetPackets.Count == 0)
            {
                // Keine BACnet-Pakete -> Bereich ausblenden
                if (BACnetAnalysisBorder != null)
                    BACnetAnalysisBorder.Visibility = Visibility.Collapsed;
                return;
            }

            // BACnet-Pakete vorhanden -> Bereich anzeigen
            if (BACnetAnalysisBorder != null)
                BACnetAnalysisBorder.Visibility = Visibility.Visible;

            // Berechne Metriken - neue Service Codes
            var broadcastCount = 0;
            var simpleAckCount = 0;      // 2
            var complexAckCount = 0;     // 3
            var whoIsCount = 0;          // 8
            var whoHasCount = 0;         // 7
            var iAmCount = 0;            // 0
            var iHaveCount = 0;          // 1
            var readPropertyCount = 0;   // 12
            var readPropertyMultCount = 0; // 14
            var writePropertyCount = 0;  // 15
            var writePropertyMultCount = 0; // 16
            var subscribeCOVCount = 0;   // 5
            var subscribeCOVPropCount = 0; // 28
            var confCOVNotifCount = 0;   // 1 (Confirmed)
            var confEventNotifCount = 0; // 2 (Confirmed)
            var addListElementCount = 0; // 8 (Confirmed)
            var removeListElementCount = 0; // 9 (Confirmed)
            var readRangeCount = 0;      // 26
            var getEventInfoCount = 0;   // 29
            var errorCount = 0;          // 5 (Error)
            var rejectCount = 0;         // 6 (Reject)
            var abortCount = 0;          // 7 (Abort)
            var reinitDeviceCount = 0;   // 20
            var totalBytes = 0;

            foreach (var packet in bacnetPackets)
            {
                if (packet.Details != null)
                {
                    // Service Code erkennen (TShark liefert numerische Codes)
                    if (packet.Details.TryGetValue("BACnet Service", out var service))
                    {
                        var svc = (service ?? "").Trim();
                        if (int.TryParse(svc, out var serviceCode))
                        {
                            // Prüfe ob Confirmed oder Unconfirmed
                            bool isConfirmed = false;
                            if (packet.Details.TryGetValue("BACnet Type", out var typeConfirmed))
                            {
                                isConfirmed = typeConfirmed?.Contains("Confirmed") == true;
                            }

                            // Service-Codes verarbeiten (depends on Confirmed/Unconfirmed)
                            if (isConfirmed)
                            {
                                // Confirmed Services
                                switch (serviceCode)
                                {
                                    case 1: confCOVNotifCount++; break;      // ConfirmedCOVNotification
                                    case 2: confEventNotifCount++; break;    // ConfirmedEventNotification
                                    case 5: subscribeCOVCount++; break;      // SubscribeCOV
                                    case 8: addListElementCount++; break;    // AddListElement
                                    case 9: removeListElementCount++; break; // RemoveListElement
                                    case 12: readPropertyCount++; break;     // ReadProperty
                                    case 14: readPropertyMultCount++; break; // ReadPropertyMultiple
                                    case 15: writePropertyCount++; break;    // WriteProperty
                                    case 16: writePropertyMultCount++; break; // WritePropertyMultiple
                                    case 20: reinitDeviceCount++; break;     // ReinitializeDevice
                                    case 26: readRangeCount++; break;        // ReadRange
                                    case 28: subscribeCOVPropCount++; break; // SubscribeCOVProperty
                                    case 29: getEventInfoCount++; break;     // GetEventInformation
                                }
                            }
                            else
                            {
                                // Unconfirmed Services
                                switch (serviceCode)
                                {
                                    case 0: iAmCount++; break;          // I-Am
                                    case 1: iHaveCount++; break;        // I-Have
                                    case 2: simpleAckCount++; break;    // SimpleACK
                                    case 3: complexAckCount++; break;   // ComplexACK
                                    case 5: errorCount++; break;        // Error
                                    case 6: rejectCount++; break;       // Reject
                                    case 7: whoHasCount++; break;       // Who-Has
                                    case 8: whoIsCount++; break;        // Who-Is
                                }
                            }
                        }
                    }

                    // Bytes zählen
                    totalBytes += (int)packet.PacketLength;
                }

                // Broadcast erkennen (nur BACnet Broadcasts über IP-Adresse)
                if (IsBroadcast(packet))
                {
                    broadcastCount++;
                }
            }

            // Berechne Raten über den tatsächlich angezeigten Zeitraum
            double durationSeconds = 1;
            if (filteredPackets.Count >= 2)
            {
                var minTs = filteredPackets.Min(p => p.Timestamp);
                var maxTs = filteredPackets.Max(p => p.Timestamp);
                durationSeconds = Math.Max(1e-6, (maxTs - minTs).TotalSeconds);
            }
            var durationMinutes = durationSeconds / 60.0;
            var whoIsPerMinute = durationMinutes > 0 ? whoIsCount / durationMinutes : 0;
            var whoHasPerMinute = durationMinutes > 0 ? whoHasCount / durationMinutes : 0;
            var broadcastPerSecond = durationSeconds > 0 ? broadcastCount / durationSeconds : 0;

            // Update Labels mit Gesamtzahl
            if (BACnetBroadcastsLabel != null)
                BACnetBroadcastsLabel.Text = $"{broadcastPerSecond:F2}/s ({broadcastCount} total)";
            if (BACnetSimpleAckLabel != null)
                BACnetSimpleAckLabel.Text = $"{simpleAckCount} total";
            if (BACnetComplexAckLabel != null)
                BACnetComplexAckLabel.Text = $"{complexAckCount} total";

            if (BACnetWhoIsLabel != null)
                BACnetWhoIsLabel.Text = $"{whoIsPerMinute:F2}/min ({whoIsCount} total)";
            if (BACnetWhoHasLabel != null)
                BACnetWhoHasLabel.Text = $"{whoHasPerMinute:F2}/min ({whoHasCount} total)";
            if (BACnetIAmLabel != null)
                BACnetIAmLabel.Text = $"{iAmCount} total";
            if (BACnetIHaveLabel != null)
                BACnetIHaveLabel.Text = $"{iHaveCount} total";

            if (BACnetReadPropertyLabel != null)
                BACnetReadPropertyLabel.Text = $"{readPropertyCount} total";
            if (BACnetReadPropertyMultLabel != null)
                BACnetReadPropertyMultLabel.Text = $"{readPropertyMultCount} total";
            if (BACnetWritePropertyLabel != null)
                BACnetWritePropertyLabel.Text = $"{writePropertyCount} total";
            if (BACnetWritePropertyMultLabel != null)
                BACnetWritePropertyMultLabel.Text = $"{writePropertyMultCount} total";

            if (BACnetSubscribeCOVLabel != null)
                BACnetSubscribeCOVLabel.Text = $"{subscribeCOVCount} total";
            if (BACnetSubscribeCOVPropLabel != null)
                BACnetSubscribeCOVPropLabel.Text = $"{subscribeCOVPropCount} total";
            if (BACnetConfCOVNotifLabel != null)
                BACnetConfCOVNotifLabel.Text = $"{confCOVNotifCount} total";
            if (BACnetConfEventNotifLabel != null)
                BACnetConfEventNotifLabel.Text = $"{confEventNotifCount} total";

            if (BACnetAddListElementLabel != null)
                BACnetAddListElementLabel.Text = $"{addListElementCount} total";
            if (BACnetRemoveListElementLabel != null)
                BACnetRemoveListElementLabel.Text = $"{removeListElementCount} total";
            if (BACnetReadRangeLabel != null)
                BACnetReadRangeLabel.Text = $"{readRangeCount} total";
            if (BACnetGetEventInfoLabel != null)
                BACnetGetEventInfoLabel.Text = $"{getEventInfoCount} total";

            if (BACnetErrorLabel != null)
                BACnetErrorLabel.Text = $"{errorCount} total";
            if (BACnetRejectLabel != null)
                BACnetRejectLabel.Text = $"{rejectCount} total";
            if (BACnetAbortLabel != null)
                BACnetAbortLabel.Text = $"{abortCount} total";
            if (BACnetReinitDeviceLabel != null)
                BACnetReinitDeviceLabel.Text = $"{reinitDeviceCount} total";
        }

        private void UpdateBACnetServicesAnalysis(List<NetworkPacket> filteredPackets)
        {
            // Erkenne BACnet-Pakete (ApplicationProtocol == "BACnet" oder Port 47808-47823)
            var bacnetPackets = filteredPackets.Where(p =>
                (p.ApplicationProtocol?.ToUpper() == "BACNET") ||
                (p.DestinationPort >= 47808 && p.DestinationPort <= 47823) ||
                (p.SourcePort >= 47808 && p.SourcePort <= 47823)).ToList();

            if (bacnetPackets.Count == 0)
            {
                if (BACnetServicesAnalysisBorder != null)
                    BACnetServicesAnalysisBorder.Visibility = Visibility.Collapsed;
                return;
            }

            if (BACnetServicesAnalysisBorder != null)
                BACnetServicesAnalysisBorder.Visibility = Visibility.Visible;

            var readPropertyCount = 0;
            var writePropertyCount = 0;
            var confirmedServicesCount = 0;
            var unconfirmedServicesCount = 0;
            var errorCount = 0;

            foreach (var packet in bacnetPackets)
            {
                if (packet.Details != null)
                {
                    // Service-Typ erkennen
                    if (packet.Details.TryGetValue("BACnet Service", out var service))
                    {
                        var svc = (service ?? "").ToLower();

                        // Read/Write Property
                        if (svc.Contains("readproperty") || svc.Contains("read-property") || svc.Contains("read property"))
                            readPropertyCount++;

                        if (svc.Contains("writeproperty") || svc.Contains("write-property") || svc.Contains("write property"))
                            writePropertyCount++;

                        // Confirmed vs Unconfirmed
                        if (svc.Contains("confirmed"))
                            confirmedServicesCount++;

                        if (svc.Contains("unconfirmed") || svc.Contains("i-am") || svc.Contains("who-is"))
                            unconfirmedServicesCount++;

                        // Error Detection
                        if (svc.Contains("error") || svc.Contains("reject") || svc.Contains("abort"))
                            errorCount++;
                    }
                }
            }

            // Update Labels
            if (BACnetReadWriteLabel != null)
                BACnetReadWriteLabel.Text = (readPropertyCount + writePropertyCount).ToString();
            if (BACnetConfirmedServLabel != null)
                BACnetConfirmedServLabel.Text = confirmedServicesCount.ToString();
            if (BACnetFastResponseLabel != null)
                BACnetFastResponseLabel.Text = readPropertyCount.ToString();
            if (BACnetErrorsLabel != null)
                BACnetErrorsLabel.Text = errorCount.ToString();
            if (BACnetNetworkMsgLabel != null)
                BACnetNetworkMsgLabel.Text = unconfirmedServicesCount.ToString();
            if (BACnetSegmentedFlagLabel != null)
                BACnetSegmentedFlagLabel.Text = writePropertyCount.ToString();
        }

        private List<DataPoint> CalculatePacketsPerSecond(List<NetworkPacket> packets, DateTime startTime, DateTime endTime)
        {
            var points = new List<DataPoint>();

            if (packets.Count == 0)
                return points;

            var duration = (endTime - startTime).TotalSeconds;
            if (duration <= 0)
                return points;

            // Adaptives Binning: max ~1000 Punkte, mindestens 100 ms
            var targetBins = 1000.0;
            var binSize = Math.Max(0.1, duration / targetBins);
            var numBins = (int)Math.Ceiling(duration / binSize);
            if (numBins < 1) numBins = 1;

            var counts = new double[numBins + 1];

            foreach (var packet in packets)
            {
                var timeOffset = (packet.Timestamp - startTime).TotalSeconds;
                if (timeOffset < 0) continue;
                var binIndex = (int)(timeOffset / binSize);
                if (binIndex < 0) continue;
                if (binIndex > numBins) binIndex = numBins;
                counts[binIndex] += 1.0;
            }

            for (int i = 0; i <= numBins; i++)
            {
                var x = i * binSize;
                var y = counts[i] / binSize; // Pakete pro Sekunde
                points.Add(new DataPoint(x, y));
            }

            return points;
        }

        private void StartTimeSlider_ValueChanged(object sender, System.Windows.RoutedPropertyChangedEventArgs<double> e)
        {
            // Stelle sicher, dass Start nicht über Ende hinausgeht
            if (EndTimeSlider != null && StartTimeSlider != null && StartTimeSlider.Value > EndTimeSlider.Value)
            {
                EndTimeSlider.Value = StartTimeSlider.Value;
            }
            DebounceUpdateChart();
        }

        private void EndTimeSlider_ValueChanged(object sender, System.Windows.RoutedPropertyChangedEventArgs<double> e)
        {
            // Stelle sicher, dass Ende nicht unter Start liegt
            if (StartTimeSlider != null && EndTimeSlider != null && EndTimeSlider.Value < StartTimeSlider.Value)
            {
                StartTimeSlider.Value = EndTimeSlider.Value;
            }
            DebounceUpdateChart();
        }

        private void DebounceUpdateChart()
        {
            _debounceTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(120) };
            _debounceTimer.Stop();
            _debounceTimer.Tick -= DebounceTimer_Tick;
            _debounceTimer.Tick += DebounceTimer_Tick;
            _debounceTimer.Start();
        }

        private void DebounceTimer_Tick(object? sender, EventArgs e)
        {
            _debounceTimer?.Stop();
            UpdateChart();
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

        // Verhindert Zoom/Pan per Maus-/Strg+Mausrad und leitet das Ereignis an den übergeordneten ScrollViewer weiter
        private void PlotView_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            e.Handled = true; // Chart soll nicht scrollen/zoomen

            if (sender is DependencyObject d)
            {
                var parent = FindScrollViewer(d);
                var sv = parent;
                if (sv != null)
                {
                    // Neues Ereignis an den ScrollViewer weiterreichen
                    var args = new MouseWheelEventArgs(e.MouseDevice, e.Timestamp, e.Delta)
                    {
                        RoutedEvent = UIElement.MouseWheelEvent,
                        Source = sender
                    };
                    sv.RaiseEvent(args);
                }
            }
        }

        private ScrollViewer? FindScrollViewer(DependencyObject current)
        {
            while (current != null)
            {
                if (current is ScrollViewer sv)
                    return sv;
                current = VisualTreeHelper.GetParent(current);
            }
            return null;
        }

        private void UpdateBACnetReadPropertiesAnalysis(List<NetworkPacket> filteredPackets)
        {
            // Erkenne BACnet-Pakete
            var bacnetPackets = filteredPackets.Where(p =>
                (p.ApplicationProtocol?.ToUpper() == "BACNET") ||
                (p.DestinationPort >= 47808 && p.DestinationPort <= 47823) ||
                (p.SourcePort >= 47808 && p.SourcePort <= 47823)).ToList();

            if (bacnetPackets.Count == 0)
            {
                // Keine BACnet-Pakete -> Bereich ausblenden
                return;
            }

            // Zähle ReadProperty/WriteProperty-Zugriffe pro BACnet-Instanz
            var propertyAccessByInstance = new Dictionary<string, int>();

            foreach (var packet in bacnetPackets)
            {
                if (packet.Details == null || packet.Details.Count == 0)
                    continue;

                var sourceIp = string.IsNullOrWhiteSpace(packet.SourceIp) ? "Unbekannt" : packet.SourceIp;
                var propertyCount = 0;

                // Zähle Property-Zugriffe in diesem Paket
                foreach (var detail in packet.Details)
                {
                    var key = detail.Key?.ToLower() ?? string.Empty;
                    var valueLower = (detail.Value ?? string.Empty).ToLower();

                    // Erkenne ReadProperty/WriteProperty
                    if (key.Contains("readproperty") || valueLower.Contains("readproperty") ||
                        (key.Contains("read") && key.Contains("property")) ||
                        (valueLower.Contains("read") && valueLower.Contains("property")))
                    {
                        propertyCount++;
                    }
                    else if (key.Contains("writeproperty") || valueLower.Contains("writeproperty") ||
                             (key.Contains("write") && key.Contains("property")) ||
                             (valueLower.Contains("write") && valueLower.Contains("property")))
                    {
                        propertyCount++;
                    }
                }

                if (propertyCount > 0)
                {
                    // Erstelle Label mit Datenbasis-Infos
                    var instance = _bacnetDb.GetInstanceForIp(sourceIp);
                    var deviceName = _bacnetDb.IpToDeviceName.TryGetValue(sourceIp, out var name) ? name : null;

                    string label;
                    if (!string.IsNullOrEmpty(instance))
                    {
                        label = string.IsNullOrEmpty(deviceName)
                            ? $"{sourceIp} (ID: {instance})"
                            : $"{sourceIp} (ID: {instance}, {deviceName})";
                    }
                    else
                    {
                        label = sourceIp;
                    }

                    if (!propertyAccessByInstance.ContainsKey(label))
                        propertyAccessByInstance[label] = 0;
                    propertyAccessByInstance[label] += propertyCount;
                }
            }
        }

        private void UpdateBACnetDatabaseStats()
        {
            // Update UI mit BACnet-Datenbasis-Statistiken
            // Zeige die Statistik an, auch wenn die Datenbank leer ist (dann zeigt sie 0)
            if (BACnetDatabaseStatsBorder != null && _bacnetDb != null)
            {
                BACnetDatabaseStatsBorder.Visibility = Visibility.Visible;

                if (BACnetDbInstanceCountLabel != null)
                    BACnetDbInstanceCountLabel.Text = (_bacnetDb.IpToInstance?.Count ?? 0).ToString();
                if (BACnetDbDeviceNameCountLabel != null)
                    BACnetDbDeviceNameCountLabel.Text = (_bacnetDb.IpToDeviceName?.Count ?? 0).ToString();
                if (BACnetDbVendorCountLabel != null)
                    BACnetDbVendorCountLabel.Text = (_bacnetDb.IpToVendorId?.Count ?? 0).ToString();
            }
        }
    }
}
