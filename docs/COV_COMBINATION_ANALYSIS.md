# COV-Kombinationsanalyse (TOP 10)

## Übersicht
Die neue COV-Kombinationsanalyse zählt jede **eindeutige Kombination** von Device-Instance und Object-Type/Instance separat. So wird sichtbar, welche spezifischen Kombinationen am häufigsten in COV-Paketen vorkommen.

## Zählweise

### Alte Logik (falsch):
```
Device 40211 → 547 COV-Pakete gesamt
```

### Neue Logik (richtig):
```
Gruppe "40211-2,19"   → 100 Pakete
Gruppe "40211-2,20"   → 85 Pakete
Gruppe "40211-2,21"   → 120 Pakete
Gruppe "40211-4,5"    → 50 Pakete
Gruppe "40211-4,6"    → 75 Pakete
Gruppe "40211-8,40211" → 117 Pakete
```

## Datenstruktur

### CovCombinationCounts
```csharp
Dictionary<string, int>
```
- **Key**: "Device-Instance-ObjectType,Instance" (z.B. "40211-2,19")
- **Value**: Anzahl der COV-Pakete mit dieser exakten Kombination

**Beispiel:**
```csharp
["40211-2,19"] = 100
["40211-2,20"] = 85
["40211-2,21"] = 120
["40211-4,5"] = 50
["40211-4,6"] = 75
["40211-8,40211"] = 117
```

## Extraktionslogik

1. **COV-Paket erkannt**: confirmed_service==1 oder unconfirmed_service==2
2. **Array-Parsing**:
   - Object-Types: "8,2" → ["8", "2"]
   - Instances: "40211,19" → ["40211", "19"]
3. **Device-Identifikation**: Finde Object-Type 8 (Device) → Instance 40211
4. **Zählen pro Kombination**:
   ```
   Für jedes Object-Type/Instance Paar im Array:
     - "40211-8,40211" → Zähler += 1
     - "40211-2,19" → Zähler += 1
     - "40211-2,20" → Zähler += 1 (NEUE Gruppe!)
   ```

## Log-Ausgabe

### Während der COV-Extraktion:
```
[STEP1:COV] Gefundene COV-Kombinationen (sortiert nach Häufigkeit):
[STEP1:COV] Device 40211 (Pakete: 547):
[STEP1:COV]   ├─ 40211 - 8,40211: 117 Pakete
[STEP1:COV]   ├─ 40211 - 2,21: 120 Pakete
[STEP1:COV]   ├─ 40211 - 2,19: 100 Pakete
[STEP1:COV]   ├─ 40211 - 2,20: 85 Pakete
[STEP1:COV]   ├─ 40211 - 4,6: 75 Pakete
[STEP1:COV]   ├─ 40211 - 4,5: 50 Pakete
[STEP1:COV] Device 1001 (Pakete: 234):
[STEP1:COV]   ├─ 1001 - 2,1: 150 Pakete
[STEP1:COV]   ├─ 1001 - 2,2: 84 Pakete
```

**Erklärung:**
- Jede Zeile zeigt eine **separate Gruppe/Kombination**
- Die Zahl am Ende ist die **Häufigkeit** dieser spezifischen Kombination
- Sortiert nach Häufigkeit (absteigend)

## UI-Darstellung

### Format für Diagram:
```
40211-2,19     (100 Pakete)
40211-2,21     (120 Pakete)
40211-8,40211  (117 Pakete)
40211-2,20     (85 Pakete)
40211-4,6      (75 Pakete)
40211-4,5      (50 Pakete)
1001-2,1       (150 Pakete)
1001-2,2       (84 Pakete)
...
```

**Balkendiagramm:**
- **Y-Achse**: Kombinationen im Format "Device-ObjectType,Instance"
- **X-Achse**: Anzahl der COV-Pakete
- **TOP 10**: Nur die 10 häufigsten Kombinationen

## Methoden

### GetTop10CovCombinations()
```csharp
List<(string CombinationKey, int PacketCount)>
```

**Return-Beispiel:**
```
("40211-8,40211", 117)
("40211-2,21", 120)
("40211-2,19", 100)
("40211-2,20", 85)
("40211-4,6", 75)
("40211-4,5", 50)
("1001-2,1", 150)
("1001-2,2", 84)
("2005-8,2005", 63)
("3010-2,10", 45)
```

### GetTop10CovPackets()
Kompatibilitätsmethode für die UI:
```csharp
List<dynamic>
  .DisplayFormat = "40211-2,19"
  .Count = 100
```

## Performance

- **Speicher**: Ein Integer pro eindeutiger Kombination (sehr effizient)
- **CPU**: Keine zusätzlichen Durchläufe durch die PCAP
- **Sortierung**: On-demand beim UI-Refresh

## Beispiel: Rohe COV-Pakete vs. Kombinationen

### Rohdaten aus PCAP:
```
Paket 1: IP=10.113.2.11, Object-Types="8,2,4", Instances="40211,19,5"
Paket 2: IP=10.113.2.11, Object-Types="8,2", Instances="40211,20"
Paket 3: IP=10.113.2.11, Object-Types="8,2,4", Instances="40211,21,6"
Paket 4: IP=10.113.2.11, Object-Types="8,2", Instances="40211,19"
```

### Gezählte Kombinationen:
```
"40211-8,40211" → wird aus jedem Paket +1 gezählt
"40211-2,19" → wird aus Paket 1 und 4 je +1 gezählt = 2 Pakete
"40211-2,20" → wird aus Paket 2 je +1 gezählt = 1 Paket
"40211-2,21" → wird aus Paket 3 je +1 gezählt = 1 Paket
"40211-4,5" → wird aus Paket 1 je +1 gezählt = 1 Paket
"40211-4,6" → wird aus Paket 3 je +1 gezählt = 1 Paket
```

## Integration

- **BACnet Analyse Fenster**: TOP 10 COV-Kombinationen Balkendiagramm
- **Debug-Logs**: Ausführliches Logging mit Häufigkeiten
- **Streaming-Verarbeitung**: Während PCAP-Import automatisch gesammelt
