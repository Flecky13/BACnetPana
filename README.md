# BACnetPana - Netzwerk-Analyse Software

![Alt text](images/APP.png)

---

## 📋 Übersicht

**BACnetPana** bietet eine leistungsstarke Schnittstelle zur Analyse von Netzwerkpaketen aus PCAP/Wireshark-Dateien mit Fokus auf BACnet-Protokollanalyse.

### Hauptfunktionen
- ✅ **Vollständige BACnet-Analyse**: Mit TShark (Wireshark) alle BACnet-Services, Object Types und Properties
- ✅ **PCAP-Dateianalyse**: Unterstützung für Wireshark-Format (.pcap, .pcapng, .cap)
- ✅ **Paket-Inspektion**: Detaillierte Ansicht aller OSI-Schichten (Ethernet, IP, TCP/UDP, BACnet)
- ✅ **BACnet-Datenbasis**: Automatische Erkennung von Devices, Instanznummern und Vendor-IDs
- ✅ **Echtzeit-Statistiken**: Automatische Berechnung von Protokoll-, IP- und Port-Statistiken
- ✅ **Grafische Visualisierung**: Diagramme und Statistik-Übersicht
- ✅ **Automatischer Fallback**: Funktioniert auch ohne TShark (eingeschränkt)

---

## ⚡ Voraussetzungen

### Empfohlen für vollständige BACnet-Unterstützung:

**Wireshark Installation** (enthält TShark)
- Download: https://www.wireshark.org/download.html
- TShark wird automatisch mit Wireshark installiert
- Ermöglicht vollständige BACnet-Protokollanalyse

### Ohne Wireshark:
- Die Anwendung funktioniert auch ohne TShark
- Verwendet SharpPcap als Fallback
- ⚠️ Eingeschränkte BACnet-Unterstützung (nur grundlegende Erkennung)

---

### PacketStatistics
Aggregierte Statistiken über alle Pakete:
- Gesamt-Zähler (Pakete, Bytes)
- Protokoll-Verteilung
- Top IP-Adressen (Source/Destination)
- Port-Häufigkeiten
- Durchsatz (Mbps), PPS

---
