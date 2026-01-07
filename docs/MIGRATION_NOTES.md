# TShark-Integration - Zusammenfassung

## Implementierte Änderungen

### 1. Neue Dateien

#### `TSharkBACnetParser.cs`
- Vollständiger Parser, der TShark (Wireshark CLI) verwendet
- Extrahiert BACnet-Daten über TShark's JSON-Export
- Automatische Erkennung des TShark-Pfades
- Unterstützt alle BACnet-Services, Object Types, Properties

**Hauptfeatures:**
- ✅ Automatische TShark-Suche in Standard-Pfaden
- ✅ JSON-basierte Datenextraktion
- ✅ Vollständige BACnet-Feldunterstützung
- ✅ Fehlerbehandlung und Logging
- ✅ Async/Await-Unterstützung

#### `PcapParserFactory.cs`
- Factory-Pattern für Parser-Auswahl
- Automatische Erkennung des besten verfügbaren Parsers
- Fallback auf SharpPcap wenn TShark nicht verfügbar

**API:**
```csharp
// Automatisch besten Parser wählen
var parser = PcapParserFactory.CreateBestAvailableParser();

// Explizite Auswahl
var parser = PcapParserFactory.CreateParser(ParserType.TShark);
```

#### `IPcapParser` Interface
- Gemeinsames Interface für alle Parser
- Ermöglicht einfachen Austausch zwischen Implementierungen

### 2. Modifizierte Dateien

#### `PcapFileReader.cs`
- ✅ Implementiert jetzt `IPcapParser`
- Keine funktionalen Änderungen
- Bleibt als Fallback-Option verfügbar

#### `MainViewModel.cs`
- ✅ Verwendet jetzt `IPcapParser` statt direkt `PcapFileReader`
- ✅ Automatische Parser-Auswahl mit `PcapParserFactory`
- ✅ Logging welcher Parser aktiv ist
- ✅ Entfernung von ungenutztem Event-Handler

### 3. Dokumentation

#### `docs/TSHARK_INTEGRATION.md`
Vollständige Dokumentation mit:
- Installation-Anweisungen
- Verwendungsbeispiele
- Liste extrahierter BACnet-Felder
- Troubleshooting
- Performance-Vergleich

## Vorteile der TShark-Lösung

| Aspekt | SharpPcap (alt) | TShark (neu) |
|--------|-----------------|--------------|
| BACnet-Services | ⚠️ Keine | ✅ Alle Services |
| Object Types | ⚠️ Keine | ✅ Vollständig |
| Properties | ⚠️ Keine | ✅ Vollständig |
| Vendor-Info | ⚠️ Teilweise | ✅ Vollständig |
| Wartung | ⚠️ Manuell | ✅ Automatisch mit Wireshark |
| Code-Komplexität | ⚠️ Hoch | ✅ Niedrig |

## BACnet-Felder (TShark)

Der TShark-Parser extrahiert folgende Felder:

```csharp
// Service-Informationen
"BACnet Type"      // Confirmed/Unconfirmed Request/Response
"BACnet Service"   // ReadProperty, WriteProperty, Who-Is, I-Am, etc.
"Invoke ID"        // Request/Response-Zuordnung

// Objekt-Informationen
"Object Type"      // Device, Analog Input, Binary Output, etc.
"Instance Number"  // Device-Instanznummer
"Property"         // Present Value, Object Name, etc.

// Vendor-Informationen
"Vendor ID"        // Numerische ID
"Vendor Name"      // Hersteller-Name
```

## Anwendung

### Automatisch (Empfohlen)

Die Anwendung wählt automatisch TShark wenn verfügbar:

```csharp
public MainViewModel()
{
    // Automatische Auswahl
    _pcapParser = PcapParserFactory.CreateBestAvailableParser();

    // Log-Ausgabe zeigt welcher Parser aktiv ist
    if (_pcapParser is TSharkBACnetParser)
        AddLog("TShark-Parser aktiviert (vollständige BACnet-Unterstützung)");
    else
        AddLog("SharpPcap-Parser aktiviert (grundlegende BACnet-Erkennung)");
}
```

### Manuell

Falls gewünscht kann der Parser explizit gewählt werden:

```csharp
// TShark erzwingen
_pcapParser = PcapParserFactory.CreateParser(ParserType.TShark);

// SharpPcap erzwingen
_pcapParser = PcapParserFactory.CreateParser(ParserType.SharpPcap);

// TShark mit Custom-Pfad
_pcapParser = new TSharkBACnetParser(@"C:\Custom\Path\tshark.exe");
```

## Installation

1. **Wireshark installieren**
   - Download: https://www.wireshark.org/download.html
   - TShark wird automatisch mitinstalliert

2. **Überprüfen**
   ```powershell
   tshark --version
   ```

3. **Anwendung starten**
   - Die Anwendung erkennt TShark automatisch
   - Fallback auf SharpPcap wenn TShark nicht verfügbar

## Testing

### TShark-Verfügbarkeit prüfen

```csharp
var parser = new TSharkBACnetParser();
bool available = parser.IsTSharkAvailable();
```

### Kommandozeile

```powershell
# BACnet-Pakete anzeigen
tshark -r capture.pcap -Y bacnet

# Services auflisten
tshark -r capture.pcap -T fields -e bacapp.service -Y bacnet

# JSON-Export (wie im Parser)
tshark -r capture.pcap -T json -e bacapp.type -e bacapp.service
```

## Migration

Die Migration ist **vollständig abwärtskompatibel**:

- ✅ Bestehender Code funktioniert weiter
- ✅ PcapFileReader bleibt als Fallback
- ✅ Automatische Auswahl des besten Parsers
- ✅ Keine API-Änderungen erforderlich

## Nächste Schritte

Mögliche Erweiterungen:

1. **Parser-Auswahl in UI**
   - Einstellungsmenü für manuelle Parser-Wahl
   - Status-Anzeige welcher Parser aktiv ist

2. **Erweiterte TShark-Features**
   - Filter direkt in TShark setzen (statt nachträglich)
   - Weitere BACnet-Felder extrahieren
   - Custom TShark-Argumente

3. **Performance-Optimierung**
   - Streaming-Verarbeitung für große Dateien
   - Progress-Reporting während TShark-Ausführung

4. **Testing**
   - Unit-Tests für TShark-Parser
   - Integration-Tests mit Sample-PCAP-Dateien
