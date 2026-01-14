using System;

namespace bacneTPana.DataAccess
{
    /// <summary>
    /// Factory für PCAP-Parser - wählt zwischen TShark und SharpPcap
    /// </summary>
    public static class PcapParserFactory
    {
        public enum ParserType
        {
            /// <summary>
            /// TShark (Wireshark CLI) - Beste BACnet-Unterstützung
            /// </summary>
            TShark,

            /// <summary>
            /// SharpPcap - Manuelle Implementierung (Fallback)
            /// </summary>
            SharpPcap
        }

        /// <summary>
        /// Erstellt einen Parser basierend auf dem Typ
        /// </summary>
        public static IPcapParser CreateParser(ParserType type, string? tsharkPath = null)
        {
            return type switch
            {
                ParserType.TShark => new TSharkBACnetParser(tsharkPath),
                ParserType.SharpPcap => new PcapFileReader(),
                _ => throw new ArgumentException($"Unbekannter Parser-Typ: {type}")
            };
        }

        /// <summary>
        /// Erstellt automatisch den besten verfügbaren Parser
        /// </summary>
        /// <param name="onTSharkNotFound">Callback wird aufgerufen wenn TShark nicht verfügbar ist</param>
        public static IPcapParser CreateBestAvailableParser(Action<string>? onTSharkNotFound = null)
        {
            // Versuche zuerst TShark
            try
            {
                var tsharkParser = new TSharkBACnetParser();
                if (tsharkParser.IsTSharkAvailable())
                {
                    return tsharkParser;
                }
                else
                {
                    onTSharkNotFound?.Invoke("TShark (Wireshark) nicht gefunden");
                }
            }
            catch (Exception ex)
            {
                // TShark nicht verfügbar
                onTSharkNotFound?.Invoke($"TShark nicht verfügbar: {ex.Message}");
            }

            // Fallback auf SharpPcap
            return new PcapFileReader();
        }

        /// <summary>
        /// Prüft ob TShark/Wireshark installiert ist
        /// </summary>
        public static bool IsTSharkInstalled()
        {
            try
            {
                var tsharkParser = new TSharkBACnetParser();
                return tsharkParser.IsTSharkAvailable();
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Interface für PCAP-Parser
    /// </summary>
    public interface IPcapParser
    {
        event EventHandler<string>? ProgressChanged;
        bacneTPana.Models.BACnetDatabase BACnetDb { get; }
        System.Threading.Tasks.Task<System.Collections.Generic.List<bacneTPana.Models.NetworkPacket>> ReadPcapFileAsync(string filePath, System.Threading.CancellationToken cancellationToken = default);
    }
}
