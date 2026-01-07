# BACnetPana - Netzwerk-Analyse Software

**Eine moderne C# WPF-Anwendung zur Analyse von Wireshark PCAP-Dateien mit vollständiger BACnet-Unterstützung**

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
- ✅ **MVVM-Architektur**: Moderne, wartbare Applikationsstruktur
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

### Entwicklung:
- .NET 10.0 SDK oder höher
- Visual Studio 2022 oder höher (optional)

---

## 🚀 Installation & Start

### 1. Wireshark installieren (empfohlen)
```bash
# Download von https://www.wireshark.org/download.html
# Installieren Sie Wireshark - TShark wird automatisch mitinstalliert
```

### 2. Überprüfen Sie die TShark-Installation
```powershell
tshark --version
# Sollte die TShark-Version anzeigen
```

### 3. Anwendung starten
```bash
dotnet run --project src/BACnetAna.UI
# Oder öffnen Sie BACnetAna.sln in Visual Studio
```

### 4. Status überprüfen
- Die Anwendung zeigt beim Start an, welcher Parser aktiv ist
- Button "ℹ️ Wireshark" in der Toolbar zeigt den aktuellen Status

---

## 📊 BACnet-Analyse-Features

### Mit TShark (vollständig):
- ✅ Alle BACnet-Services (ReadProperty, WriteProperty, Who-Is, I-Am, etc.)
- ✅ Object Types (Device, Analog Input, Binary Output, etc.)
- ✅ Instance Numbers und Property Identifiers
- ✅ Vendor-Informationen
- ✅ Request/Response-Zuordnung via Invoke ID

### Ohne TShark (Fallback):
- ⚠️ Grundlegende BACnet-Paketerkennung (Port 47808-47823)
- ⚠️ Keine detaillierte Service-Analyse
- ⚠️ Begrenzte Device-Informationen

---

## 🏗️ Projektstruktur

```
BACnetAna/
├── BACnetAna.sln                          # Visual Studio Solution
├── README.md                              # Diese Datei
├── docs/
│   ├── TSHARK_INTEGRATION.md              # TShark-Dokumentation
│   └── MIGRATION_NOTES.md                 # Änderungsnotizen
└── src/
    ├── BACnetAna.Models/                  # Datenmodelle
    │   ├── NetworkPacket.cs               # Paket-Datenstruktur
    │   ├── PacketStatistics.cs            # Statistik-Modell
    │   ├── BACnetDatabase.cs              # BACnet-Gerätedatenbank
    │   └── ProtocolInfo.cs                # Protokoll-Informationen
    │
    ├── BACnetAna.DataAccess/              # Datenschicht
    │   ├── TSharkBACnetParser.cs          # TShark-basierter Parser (empfohlen)
    │   ├── PcapFileReader.cs              # SharpPcap-Parser (Fallback)
    │   ├── PcapParserFactory.cs           # Automatische Parser-Auswahl
    │   └── StatisticsCalculator.cs        # Statistik-Berechnung
    │
    ├── BACnetAna.Core/                    # Geschäftslogik / ViewModels
    │   └── ViewModels/
    │       ├── MainViewModel.cs           # Haupt-ViewModel (MVVM)
    │       └── StatisticsViewModel.cs     # Statistik-ViewModel
    │
    └── BACnetAna.UI/                      # WPF-Benutzeroberfläche
        ├── MainWindow.xaml                # Hauptfenster (XAML)
        ├── MainWindow.xaml.cs             # Code-Behind
        ├── AnalysisWindow.xaml            # Analyse-Fenster
        ├── App.xaml
        └── App.xaml.cs
```

---

## 🔧 Technologie-Stack

| Komponente | Technologie | Version |
|-----------|------------|---------|
| **Framework** | .NET | 10.0 |
| **GUI** | WPF | Windows-native |
| **MVVM** | CommunityToolkit.Mvvm | 8.3.2 |
| **PCAP-Parsing** | SharpPcap | 6.3.1 |
| **Paket-Analyse** | PacketDotNet | 1.4.8 |
| **Grafiken** | OxyPlot.Wpf | 2.1.2 |

---

## 🚀 Installation & Verwendung

### Voraussetzungen
- Windows 10/11 oder höher
- .NET 10.0 SDK

### Projekt öffnen
```bash
# Projekt klonen/öffnen
cd d:\github\BACnetAna

# Bauen
dotnet build

# Ausführen
dotnet run --project src/BACnetAna.UI
```

### PCAP-Datei analysieren
1. Klick auf **"📁 PCAP-Datei öffnen"** Button
2. Wähle eine `.pcap` oder `.cap` Datei aus
3. Pakete werden automatisch geladen und analysiert
4. Statistiken werden rechts in der Sidebar angezeigt

---

## 📊 Datenmodelle

### NetworkPacket
Repräsentiert ein einzelnes Netzwerkpaket mit:
- **Layer 2 (Ethernet)**: MAC-Adressen, Typ
- **Layer 3 (IP)**: Source/Destination IP, Protocol, TTL
- **Layer 4 (Transport)**: Ports (TCP/UDP), TCP-Flags
- **Payload**: Raw-Daten, Hex-Darstellung
- **Metadaten**: Timestamp, Größe, Zusammenfassung

```csharp
var packet = new NetworkPacket
{
    PacketNumber = 1,
    Timestamp = DateTime.Now,
    SourceIp = "192.168.1.100",
    DestinationIp = "8.8.8.8",
    Protocol = "TCP",
    SourcePort = 52345,
    DestinationPort = 443
};
```

### PacketStatistics
Aggregierte Statistiken über alle Pakete:
- Gesamt-Zähler (Pakete, Bytes)
- Protokoll-Verteilung
- Top IP-Adressen (Source/Destination)
- Port-Häufigkeiten
- Durchsatz (Mbps), PPS

---

## 🔌 PCAP-Parser Verwendung

```csharp
var reader = new PcapFileReader();

// Event-Handler für Fortschritt
reader.ProgressChanged += (s, msg) => Console.WriteLine(msg);
reader.PacketRead += (s, args) =>
{
    Console.WriteLine($"Paket {args.TotalPackets} geladen");
};

// Datei lesen
var packets = reader.ReadPcapFile("capture.pcap");

// Statistiken berechnen
var calculator = new StatisticsCalculator();
var stats = calculator.CalculateStatistics(packets);

Console.WriteLine($"Gesamt: {stats.TotalPackets} Pakete, {stats.TotalBytes} Bytes");
Console.WriteLine($"Durchsatz: {stats.GetMegabitsPerSecond():F2} Mbps");
```

---

##  MVVM-Architektur

Das Projekt folgt dem **MVVM-Pattern** (Model-View-ViewModel):

```
┌─────────────────────────────────────┐
│   View (MainWindow.xaml)            │
│   ├─ DataGrid (Pakete)              │
│   ├─ TreeView (Details)             │
│   └─ Charts (Statistiken)           │
└────────────────┬────────────────────┘
                 │ Binding/Command
┌────────────────▼────────────────────┐
│   ViewModel (MainViewModel)          │
│   ├─ LoadPcapFileCommand             │
│   ├─ Packets (Observable)            │
│   ├─ SelectedPacket                  │
│   └─ PacketStatistics               │
└────────────────┬────────────────────┘
                 │ Uses
┌────────────────▼────────────────────┐
│   Models & DataAccess               │
│   ├─ PcapFileReader                 │
│   ├─ StatisticsCalculator           │
│   ├─ NetworkPacket                  │
│   └─ PacketStatistics              │
└─────────────────────────────────────┘
```

---

## 🎯 Geplante Erweiterungen

- [ ] **Erweiterte Filter** (IP, Port, Protokoll, Zeitsbereich)
- [ ] **Export-Funktionen** (CSV, JSON, PDF-Bericht)
- [ ] **Live-Packet-Capture** (Echtzeitaufnahme von Netzwerk-Traffic)
- [ ] **Erweiterte Diagramme** (Flow-Visualisierung, Heatmaps)
- [ ] **Protokoll-Dissection** (HTTP, DNS, FTP Payload-Analyse)
- [ ] **Suchen & Bookmark** (Schnelle Navigation zu interessanten Paketen)
- [ ] **Dunkler Modus** (UI-Verbesserungen)

---

## 📝 Dateiumlauf

### 1. PCAP-Datei laden (`PcapFileReader.cs`)
```
PCAP-Datei → SharpPcap Device → PacketCapture Objects
```

### 2. Pakete parsen (`PcapFileReader.cs`)
```
PacketCapture → PacketDotNet.Packet → Ethernet/IP/TCP/UDP Extraction
```

### 3. NetworkPacket-Modelle erstellen
```
Extracted Layers → NetworkPacket-Objekt mit allen Informationen
```

### 4. In Observable Collection laden
```
List<NetworkPacket> → ObservableCollection → DataGrid Binding
```

### 5. Statistiken berechnen (`StatisticsCalculator.cs`)
```
List<NetworkPacket> → Aggregation → PacketStatistics
```

### 6. UI aktualisieren
```
Statistics → ViewModel → XAML Bindings → Charts/Labels
```

---

## 🐛 Bekannte Limitierungen

1. **Zeitstempel**: Nutzt aktuelle Systemzeit statt PCAP-Timestamp (API-Änderung in SharpPcap)
2. **ICMP-Felder**: Manche ICMP-Felder werden teilweise verarbeitet
3. **IPv6**: Grundunterstützung vorhanden, aber nicht vollständig getestet
4. **Performance**: Bei Dateien >100k Paketen kann die UI langsam werden

---

## 📚 Basis-Architektur (Original-Software vs. BACnetAna)

| Aspekt | Original Visual_BACnet | BACnetAna |
|--------|-----|---------|
| **Sprache** | Python + JavaScript | C# |
| **GUI-Framework** | Electron | WPF |
| **Backend-Server** | Flask/Tornado | MVVM-Services |
| **PCAP-Parser** | PyShark | SharpPcap + PacketDotNet |
| **Datenverarbeitung** | Pandas/NumPy | LINQ / Collections |
| **Datenbank** | Pickle | In-Memory Collections |
| **Visualisierung** | D3.js / Web | OxyPlot / WPF Controls |

---

## 🔗 Abhängigkeiten

Alle NuGet-Pakete werden automatisch durch `dotnet restore` installiert:

```xml
<!-- BACnetAna.UI -->
<PackageReference Include="CommunityToolkit.Mvvm" Version="8.3.2" />
<PackageReference Include="OxyPlot.Wpf" Version="2.1.2" />

<!-- BACnetAna.DataAccess -->
<PackageReference Include="SharpPcap" Version="6.3.1" />
<PackageReference Include="PacketDotNet" Version="1.4.8" />

<!-- BACnetAna.Core -->
<PackageReference Include="CommunityToolkit.Mvvm" Version="8.3.2" />
```

---

## 💡 Tipps für Erweiterung

### Neues ViewModel hinzufügen
1. Erstelle `class MyViewModel : ObservableObject` in `BACnetAna.Core/ViewModels/`
2. Nutze `[ObservableProperty]` Attribute für automatische Property-Generierung
3. Verwende `[RelayCommand]` für Commands

### Neues Fenster/Control hinzufügen
1. Erstelle `MyWindow.xaml` + `MyWindow.xaml.cs` in `BACnetAna.UI/`
2. Setze `DataContext = new MyViewModel();` im Code-Behind
3. Binde Properties über `{Binding PropertyName}` in XAML

### Neue Analyse-Funktion
1. Erweitere `StatisticsCalculator.cs` mit neuer Methode
2. Rufe aus `MainViewModel` auf
3. Binde Ergebnis an UI durch Property-Binding

---

## 📞 Support & Debugging

### Build erfolgreich, aber Fehler beim Ausführen?
- Stelle sicher, dass `.NET 10.0 SDK` installiert ist: `dotnet --version`
- Lö Projekt neu: `dotnet clean && dotnet build`

### PCAP-Datei wird nicht erkannt?
- Prüfe ob Dateiformat `.pcap` oder `.cap` ist
- Versuche mit Test-Datei aus `d:\github\Visual_BACnet_Evaluation\app\backend\pcap\`

### Performance-Probleme?
- Für große Dateien: Reduziere angezeigte Pakete durch Filter
- Nutze `GetNextPacket()` mit asynchronem Laden

---

## 📄 Lizenz

Nicht spezifiziert (zu definieren basierend auf Original-Projekt)

---

**Erstellt:** Januar 2026
**Projektname:** BACnetAna
**Entwickelt für:** Netzwerk-Paketanalyse & Visualisierung
**Status:** ✅ Produktiv (Core-Funktionalität)
