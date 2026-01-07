# TShark-Integration für BACnet-Analyse

## Übersicht

Die Anwendung unterstützt jetzt zwei Parsing-Methoden für PCAP-Dateien:

1. **TShark-Parser** (empfohlen) - Verwendet Wireshark's TShark CLI für vollständige BACnet-Unterstützung
2. **SharpPcap-Parser** (Fallback) - Manuelle Implementierung mit grundlegender BACnet-Erkennung

## TShark Installation

### Windows

1. **Wireshark installieren**
   - Download: https://www.wireshark.org/download.html
   - TShark wird automatisch mit Wireshark installiert
   - Standardpfad: `C:\Program Files\Wireshark\tshark.exe`

2. **Überprüfung**
   ```powershell
   tshark --version
   ```

### Vorteile von TShark

✅ **Vollständige BACnet-Unterstützung**
- Alle BACnet-Services (ReadProperty, WriteProperty, Who-Is, I-Am, etc.)
- Object Types und Instance Numbers
- Property Identifiers
- Vendor-Informationen
- Fehlerbehandlung und Fragmentierung

✅ **Wartbarkeit**
- Kein manuelles Protokoll-Parsing
- Automatische Updates mit Wireshark
- Bewährte und getestete Implementierung

✅ **Performance**
- Optimiertes Parsing
- Effiziente Feldextraktion
- JSON-basierte Datenübergabe

## Verwendung in der Anwendung

### Automatische Parser-Auswahl

```csharp
// Erstellt automatisch den besten verfügbaren Parser
var parser = PcapParserFactory.CreateBestAvailableParser();
var packets = await parser.ReadPcapFileAsync("capture.pcap");
```

### Manuelle Parser-Auswahl

```csharp
// TShark explizit verwenden
var parser = PcapParserFactory.CreateParser(
    PcapParserFactory.ParserType.TShark);

// SharpPcap als Fallback
var parser = PcapParserFactory.CreateParser(
    PcapParserFactory.ParserType.SharpPcap);
```

### TShark-Pfad manuell angeben

```csharp
var parser = new TSharkBACnetParser(@"C:\Custom\Path\tshark.exe");
```

## Extrahierte BACnet-Felder

Der TShark-Parser extrahiert folgende BACnet-Informationen:

| Feld | TShark Filter | Beschreibung |
|------|---------------|--------------|
| Service Type | `bacapp.type` | Confirmed/Unconfirmed Request/Response |
| Confirmed Service | `bacapp.confirmed_service` | ReadProperty, WriteProperty, etc. |
| Unconfirmed Service | `bacapp.unconfirmed_service` | Who-Is, I-Am, etc. |
| Invoke ID | `bacapp.invoke_id` | Request/Response-Zuordnung |
| Object Type | `bacapp.objectType` | Device, Analog Input, Binary Output, etc. |
| Instance Number | `bacapp.instance_number` | Device-Instanznummer |
| Property ID | `bacapp.property_identifier` | Present Value, Object Name, etc. |
| Vendor ID | `bacapp.vendor_identifier` | Numerische Vendor-ID |
| Object Name | `bacapp.object_name` | Name des Objekts |

## Beispiel: Extrahierte Daten

```json
{
  "BACnet Type": "Confirmed-Request",
  "BACnet Service": "readProperty",
  "Invoke ID": "42",
  "Object Type": "analog-input",
  "Instance Number": "12345",
  "Property": "present-value",
  "Vendor ID": "260",
  "Object Name": "Temperature Sensor"
}
```

## Fehlerbehandlung

Falls TShark nicht verfügbar ist:
- Die Anwendung fällt automatisch auf SharpPcap zurück
- Eine Warnung wird angezeigt
- Grundlegende BACnet-Erkennung bleibt verfügbar

## Performance-Vergleich

| Parser | BACnet-Details | Performance | Wartung |
|--------|----------------|-------------|---------|
| TShark | ✅ Vollständig | ⚡ Sehr gut | ✅ Einfach |
| SharpPcap | ⚠️ Begrenzt | ⚡ Gut | ⚠️ Manuell |

## TShark-Kommandos zum Testen

### BACnet-Pakete anzeigen
```bash
tshark -r capture.pcap -Y bacnet
```

### BACnet-Services exportieren
```bash
tshark -r capture.pcap -T fields -e bacapp.service -Y bacnet
```

### JSON-Export (wie in der Anwendung)
```bash
tshark -r capture.pcap -T json -e bacapp.type -e bacapp.service
```

## Troubleshooting

### TShark nicht gefunden
```
FileNotFoundException: TShark wurde nicht gefunden
```
**Lösung:** Wireshark installieren oder Pfad manuell angeben

### Keine BACnet-Pakete
- Überprüfen Sie, ob die PCAP-Datei BACnet-Traffic enthält (Port 47808)
- Testen Sie mit: `tshark -r capture.pcap -Y "udp.port == 47808"`

### JSON-Parse-Fehler
- Überprüfen Sie die TShark-Version (min. 2.0)
- Testen Sie: `tshark --version`

## Weiterführende Links

- [Wireshark Download](https://www.wireshark.org/download.html)
- [TShark Dokumentation](https://www.wireshark.org/docs/man-pages/tshark.html)
- [BACnet Display Filter Referenz](https://www.wireshark.org/docs/dfref/b/bacapp.html)
