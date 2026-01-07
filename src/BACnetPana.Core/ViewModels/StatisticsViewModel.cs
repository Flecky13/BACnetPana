using System;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using BACnetPana.Models;

namespace BACnetPana.Core.ViewModels
{
    public partial class StatisticsViewModel : ObservableObject
    {
        [ObservableProperty]
        private PacketStatistics statistics = new();

        [ObservableProperty]
        private ObservableCollection<ProtocolChartData> protocolData;

        [ObservableProperty]
        private ObservableCollection<ProtocolChartData> hierarchicalProtocolData;

        [ObservableProperty]
        private ObservableCollection<IpChartData> sourceIpData;

        [ObservableProperty]
        private ObservableCollection<PortChartData> portData;

        public StatisticsViewModel()
        {
            protocolData = new ObservableCollection<ProtocolChartData>();
            hierarchicalProtocolData = new ObservableCollection<ProtocolChartData>();
            sourceIpData = new ObservableCollection<IpChartData>();
            portData = new ObservableCollection<PortChartData>();
        }

        public void UpdateFromStatistics(PacketStatistics stats)
        {
            Statistics = stats;
            RefreshCharts();
        }

        private void RefreshCharts()
        {
            if (Statistics == null)
                return;

            // Update Protocol Chart
            ProtocolData.Clear();
            foreach (var proto in Statistics.ProtocolCount)
            {
                ProtocolData.Add(new ProtocolChartData
                {
                    Protocol = proto.Key,
                    PacketCount = proto.Value,
                    ByteCount = Statistics.ProtocolBytes.ContainsKey(proto.Key) ? Statistics.ProtocolBytes[proto.Key] : 0
                });
            }

            // Update Hierarchical Protocol Chart
            HierarchicalProtocolData.Clear();
            foreach (var proto in Statistics.HierarchicalProtocolCount.OrderByDescending(x => x.Value))
            {
                HierarchicalProtocolData.Add(new ProtocolChartData
                {
                    Protocol = proto.Key,
                    PacketCount = proto.Value,
                    ByteCount = Statistics.HierarchicalProtocolBytes.ContainsKey(proto.Key) ? Statistics.HierarchicalProtocolBytes[proto.Key] : 0
                });
            }

            // Update Source IP Chart
            SourceIpData.Clear();
            foreach (var ip in Statistics.IpSourceCount.OrderByDescending(x => x.Value).Take(10))
            {
                SourceIpData.Add(new IpChartData
                {
                    IpAddress = ip.Key,
                    PacketCount = ip.Value
                });
            }

            // Update Port Chart
            PortData.Clear();
            foreach (var port in Statistics.DestinationPortCount.OrderByDescending(x => x.Value).Take(10))
            {
                PortData.Add(new PortChartData
                {
                    Port = port.Key,
                    PacketCount = port.Value
                });
            }
        }
    }

    public class ProtocolChartData
    {
        public string Protocol { get; set; } = string.Empty;
        public int PacketCount { get; set; }
        public long ByteCount { get; set; }
    }

    public class IpChartData
    {
        public string IpAddress { get; set; } = string.Empty;
        public int PacketCount { get; set; }
    }

    public class PortChartData
    {
        public int Port { get; set; }
        public int PacketCount { get; set; }
    }
}
