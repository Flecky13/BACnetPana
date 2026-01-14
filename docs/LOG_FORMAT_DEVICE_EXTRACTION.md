# BACnet Device-Erkennung - Debug-Log Beispiele

## Gesamtablauf beim PCAP-Import

```
[STEP1] Start: Extrahiere Device Instanzen...
[STEP1] Gefunden: 45 Zeilen zur Analyse
[STEP1:IAM] Gerät 1: IP=192.168.1.10, Instance=1001
[STEP1:IAM]   └─ Quelle: Feld 'bacapp.instance_number' aus I-Am Paket (TShark)
[STEP1:IAM] Gerät 2: IP=192.168.1.11, Instance=1002
[STEP1:IAM]   └─ Quelle: Feld 'bacapp.instance_number' aus I-Am Paket (TShark)
[STEP1:IAM] Gerät 3: IP=192.168.1.15, Instance=1005
[STEP1:IAM]   └─ Quelle: Pattern 'device,XXXXX' aus I-Have Info-Spalte: 'I-Have, device,1005'
[STEP1] Gesamt (I-Am/I-Have): 3 BACnet-Geräte gefunden
[STEP1] Start: Extrahiere zusätzliche Devices aus COV-Paketen...
[STEP1] COV-Pakete: 128 Zeilen analysiert
[STEP1:COV] Gerät 1: IP=192.168.1.20, Instance=2001
[STEP1:COV]   ├─ Object-Type: 8
[STEP1:COV]   ├─ Instance-Raw: 2001
[STEP1:COV]   └─ Quelle: COV-Paket (confirmed_service==1 oder unconfirmed_service==2)
[STEP1:COV] Gerät 2: IP=192.168.1.21, Instance=3050
[STEP1:COV]   ├─ Object-Type: 8
[STEP1:COV]   ├─ Instance-Raw: 3050
[STEP1:COV]   └─ Quelle: COV-Paket (confirmed_service==1 oder unconfirmed_service==2)
[STEP1:COV] IP=192.168.1.10 IGNORIERT (bereits vorhanden: 1001)
[STEP1] Zusätzlich aus COV: 2 Devices gefunden
```

## Paket-Level Verarbeitung während Stream-Parsing

### Beispiel 1: I-Am Paket
```
[PACKET] IP=192.168.1.10: Erkannt als I-Am Paket
[PACKET] IP=192.168.1.10: PRIORITÄT 1 - Instance aus 'bacapp.instance_number'=1001 → 1001
[DEVICE] IP=192.168.1.10: GESPEICHERT Instance=1001 (Typ: I-Am, Quelle: Feld 'bacapp.instance_number' (Wert: 1001))
```
**Hinweis:** Device-Namen und Vendor-IDs werden im Hintergrund extrahiert, aber nicht geloggt (um das Log sauber zu halten)

### Beispiel 2: I-Have Paket
```
[PACKET] IP=192.168.1.15: Erkannt als I-Am Paket
[PACKET] IP=192.168.1.15: PRIORITÄT 2 - Instance aus 'device,'-Pattern in 'bacapp.service'=I-Have, device,1005 → 1005
[DEVICE] IP=192.168.1.15: GESPEICHERT Instance=1005 (Typ: I-Am, Quelle: Pattern 'device,XXXXX' aus Feld 'bacapp.service' (Wert: I-Have, device,1005))
```

### Beispiel 3: COV-Paket (Confirmed)
```
[STEP1:COV] Gerät 1: IP=10.113.2.11, Instance=40211
[STEP1:COV]   ├─ Object-Type: 8,2
[STEP1:COV]   ├─ Instance-Raw: 40211,19
[STEP1:COV]   └─ Quelle: COV-Paket - Object-Type 8 (Device) mit Instance 40211
```

**Erklärung:**
- **Object-Type: 8,2** → Array mit 2 Werten
  - Position 0: `8` = Device (wird verwendet)
  - Position 1: `2` = Binary Value (ignoriert)
- **Instance-Raw: 40211,19** → Array mit 2 Werten, parallel zu Object-Type
  - Position 0: `40211` = Instance für Object-Type 8 → **wird als Device-ID verwendet**
  - Position 1: `19` = Instance für Object-Type 2 (nicht relevant)

**Logik:** Suche nach Object-Type 8 (Device) und nimm die entsprechende Instance-Nummer

### Beispiel 4: COV-Paket (Unconfirmed)
```
[PACKET] IP=192.168.1.21: Erkannt als COV Paket (unconfirmed_service==2)
[PACKET] IP=192.168.1.21: PRIORITÄT 1 - Instance aus 'bacapp.instance_number'=3050 → 3050
[DEVICE] IP=192.168.1.21: GESPEICHERT Instance=3050 (Typ: COV, Quelle: Feld 'bacapp.instance_number' (Wert: 3050))
```

### Beispiel 5: Doppelter Eintrag (ignoriert)
```
[PACKET] IP=192.168.1.10: Erkannt als COV Paket (confirmed_service==1)
[PACKET] IP=192.168.1.10: PRIORITÄT 1 - Instance aus 'bacapp.instance_number'=1001 → 1001
[DEVICE] IP=192.168.1.10: IGNORIERT Instance=1001 (bereits vorhanden: 1001)
```

## Log-Format Erklärung

### [STEP1] - Batch-Verarbeitung (TShark)
```
[STEP1:IAM]  - I-Am/I-Have Extraktion via TShark
[STEP1:COV]  - COV-Paket Extraktion via TShark
```

**Ausgabe enthält:**
- IP-Adresse
- Instance-Number
- Quellfeld / Quelltyp
- (Optional) Rohe Werte für Debugging

### [PACKET] - Stream-Parsing Paket-Level
```
[PACKET]     - Paketersatzanalyse während des Streaming
```

**Ausgabe enthält:**
- IP-Adresse
- Erkannter Pakettyp (I-Am, COV, Sonstige)
- Service-Codes (falls relevant)
- Priorität beim Extrahieren
- Extrahierte Feldwerte

### [DEVICE] - Finale Speicherung
```
[DEVICE]     - Speicherentscheidung für IP-zu-Instance Mapping
```

**Ausgabe enthält:**
- IP-Adresse
- Instance-Number
- Status (GESPEICHERT, IGNORIERT)
- Pakettyp
- Herkunftsquelle (welches Feld, welcher Pakettyp)

## Extraktionsquellen (Prioritäten)

### PRIORITÄT 1: bacapp.instance_number
```
Quelle: Feld 'bacapp.instance_number' (Wert: 1001)
Verwendet bei: I-Am Paketen, COV-Paketen
```

### PRIORITÄT 2: device,XXXXX Pattern
```
Quelle: Pattern 'device,XXXXX' aus Feld 'bacapp.service' (Wert: I-Have, device,1005)
Verwendet bei: I-Have Paketen, wenn bacapp.instance_number fehlt
Extraktionslogik: Split('device,') → ExtractInstanceNumber()
```

### PRIORITÄT 3: Object-Identifier Felder
```
Quelle: Feld 'bacapp.objectidentifier' (Wert: device:1005:8)
Verwendet bei: Beliebigen BACnet-Paketen, wenn Priorität 1 & 2 nicht vorhanden
Feldmuster:
  - bacapp.objectidentifier
  - bacapp.device_instance
  - bacapp.object_instance
```

## Zusammenfassung

Die Logs ermöglichen eine vollständige Nachverfolgung:

1. **WOHER**: Welches Feld/Paket die Instance-Number kam
2. **WIE**: Welche Extraktionslogik verwendet wurde
3. **WARUM**: Welche Priorität entschied (I-Am > COV > Sonstige)
4. **VERIFIZIERUNG**: Ob der Eintrag gespeichert oder ignoriert wurde

Dies ermöglicht schnelles Debugging bei fehlenden oder falschen Device-IDs.
