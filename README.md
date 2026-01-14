# BACnetPana - Netzwerk-Analyse Software

![Alt text](images/APP.png)

## Netzwerk-Analyse für BACnet & PCAP-Dateien

**BACnetPana** analysiert PCAP-Dateien mit Fokus auf BACnet-Protokolle.

### Hauptfunktionen
- ✅ **Vollständige BACnet-Analyse**: Mit TShark (Wireshark) alle BACnet-Services, Object Types und Properties
- ✅ **PCAP-Dateianalyse**: Unterstützung für Wireshark-Format (.pcap, .pcapng, .cap)
- ✅ **Paket-Inspektion**: Detaillierte Ansicht aller OSI-Schichten (Ethernet, IP, TCP/UDP, BACnet)
- ✅ **BACnet-Datenbasis**: Automatische Erkennung von Devices, Instanznummern und Vendor-IDs
- ✅ **Echtzeit-Statistiken**: Automatische Berechnung von Protokoll-, IP- und Port-Statistiken
- ✅ **Grafische Visualisierung**: Diagramme und Statistik-Übersicht
- ✅ **Automatischer Fallback**: Funktioniert auch ohne TShark (eingeschränkt)

---

## Voraussetzungen
- **.NET 10.0**
- **Wireshark** (empfohlen) - enthält TShark für vollständige BACnet-Analyse
  - Download: https://www.wireshark.org/download.html
- Ohne TShark: eingeschränkte BACnet-Unterstützung via SharpPcap
