# BACnet Device-Erkennung - COV-Paket-Verbesserung

## Übersicht
Die BACnet TOP 10 Geräte-Erkennung wurde um die Verarbeitung von **COV-Paketen** (Change of Value) erweitert. Dies ermöglicht die Identifikation von zusätzlichen Device-IDs, wenn keine I-Am oder I-Have Pakete im PCAP vorhanden sind.

## Technische Details

### Zuvor (nur I-Am/I-Have)
```
Filter: bacapp.unconfirmed_service == 0 || bacapp.unconfirmed_service == 1
- Service 0: I-Am
- Service 1: I-Have
```

Diese Pakete werden schnell gesendet, möglicherweise aber nicht in allen Netzwerk-Captures enthalten.

### Jetzt (I-Am/I-Have + COV)

#### 1. I-Am und I-Have Pakete (Priorität 1)
```
Filter: bacapp.unconfirmed_service == 0 || bacapp.unconfirmed_service == 1
Extrahiert:
- ip.src
- bacapp.instance_number (I-Am)
- bacapp.instance_number aus Info-String (I-Have)
```

**Höchste Priorität:** Device-IDs werden immer übernommen

#### 2. COV-Pakete (Priorität 2)
```
Filter: bacapp.confirmed_service == 1 || bacapp.unconfirmed_service == 2
- Service 1 (Confirmed): Subscribed COV Notification
- Service 2 (Unconfirmed): Unconfirmed COV Notification
```

Extrahiert:
- `ip.src` - Source-IP des Geräts
- `bacapp.objectType` - Object-Type (z.B. 8 = Device)
- `bacapp.instance_number` - Instance-Number des Objekts

**Mittlere Priorität:** Device-IDs werden nur eingefügt, wenn sie noch nicht vorhanden sind

#### 3. Weitere Pakete (Priorität 3)
```
Alle anderen BACnet-Pakete mit bacapp.instance_number oder ähnlichen Feldern
```

**Niedrigste Priorität:** Device-IDs werden nur eingefügt, wenn sie noch nicht vorhanden sind

## Implementierung

### Dateien geändert
- **[BACnetDatabase.cs](../src/BACnetPana.Models/BACnetDatabase.cs)**

### Methoden hinzugefügt

#### `ExtractCovDevicesFromPcap(string pcapFilePath, string tsharkPath)`
- Private Hilfsmethode in `BACnetDatabase`
- Wird nach I-Am/I-Have Verarbeitung aufgerufen
- Nutzt TShark zum Extrahieren von COV-Paketen
- Filtert nur Pakete ohne bereits zugeordnete Device-ID

### ProcessPacket-Erweiterung
- Neuer Flag: `bool isCov` zur Laufzeit-Erkennung von COV-Paketen
- COV-Erkennung basiert auf Service-Codes:
  - `bacapp.confirmed_service == "1"`
  - `bacapp.unconfirmed_service == "2"`
- COV-Pakete werden mit niedrigerer Priorität behandelt als I-Am/I-Have

## Logging und Debug-Output

Die Verarbeitung gibt detaillierten Debug-Output aus:

```
[STEP1] Gefunden: X Zeilen zur Analyse
[STEP1]   Gerät 1: IP=192.168.1.10, Instance=1001
[STEP1]   Gerät 2: IP=192.168.1.11, Instance=1002
[STEP1] Gesamt (I-Am/I-Have): X BACnet-Geräte gefunden
[STEP1] Start: Extrahiere zusätzliche Devices aus COV-Paketen...
[STEP1] COV-Pakete: Y Zeilen analysiert
[STEP1]   COV-Gerät: IP=192.168.1.20, Object-Type=8, Instance=2001
[STEP1] Zusätzlich aus COV: Z Devices gefunden
```

## Vorteile

1. **Höhere Erfassungsrate:** Mehr Device-IDs werden erkannt, selbst wenn I-Am/I-Have-Pakete fehlen
2. **Verlässlichkeit:** COV-Pakete sind regulärer Teil des BACnet-Datenverkehrs
3. **Priorisierung:** I-Am/I-Have bleiben Priorität, COV wird nur bei Bedarf genutzt
4. **Keine Breaking Changes:** Existierende Logik bleibt unverändert

## Verwendung

Die Verbesserung wird automatisch bei jedem PCAP-Import aktiviert:

```csharp
// In TSharkBACnetParser.ReadPcapFile()
BACnetDb.ExtractIAmDevicesFromPcap(filePath);  // Jetzt auch COV!
```

## Performance-Hinweis

Die COV-Extraktion führt einen zusätzlichen TShark-Pass durch die PCAP-Datei durch. Dies hat minimale Performance-Auswirkungen:
- COV-Filter ist sehr spezifisch (nur Service 1 oder 2)
- Wird nur nach I-Am/I-Have verarbeitet (Sequenz, nicht parallel)
- Aktuell nicht in der Streaming-Pipeline, sondern als Batch-Verarbeitung
