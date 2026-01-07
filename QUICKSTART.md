# 🚀 Quick Start Guide - BACnetAna

## Wireshark/TShark erforderlich?

**Kurze Antwort:** Nein, aber **dringend empfohlen** für vollständige BACnet-Analyse!

---

## Funktionsvergleich

| Feature | ✅ MIT Wireshark | ⚠️ OHNE Wireshark |
|---------|-----------------|-------------------|
| BACnet-Pakete erkennen | ✅ Ja | ✅ Ja |
| BACnet-Services (ReadProperty, etc.) | ✅ Ja | ❌ Nein |
| Object Types (Device, Analog Input) | ✅ Ja | ❌ Nein |
| Instance Numbers | ✅ Ja | ⚠️ Teilweise |
| Property Identifiers | ✅ Ja | ❌ Nein |
| Vendor-Informationen | ✅ Ja | ❌ Nein |
| Request/Response-Zuordnung | ✅ Ja | ❌ Nein |

---

## Installation

### Option 1: Vollständige Installation (empfohlen)

#### Schritt 1: Wireshark installieren
```
1. Download: https://www.wireshark.org/download.html
2. Installer ausführen
3. TShark wird automatisch mitinstalliert
4. Fertig!
```

#### Schritt 2: Überprüfen
```powershell
# In PowerShell oder CMD:
tshark --version

# Erwartete Ausgabe:
# TShark (Wireshark) 4.x.x ...
```

#### Schritt 3: BACnetAna starten
```bash
dotnet run --project src/BACnetAna.UI
```

#### Schritt 4: Status prüfen
Im Log sollte erscheinen:
```
✅ TShark-Parser aktiviert
   → Vollständige BACnet-Unterstützung verfügbar
```

---

### Option 2: Ohne Wireshark (Fallback-Modus)

Die Anwendung funktioniert auch ohne Wireshark, aber mit eingeschränkter Funktionalität.

#### Was funktioniert:
- ✅ PCAP-Dateien öffnen
- ✅ Netzwerkpakete anzeigen
- ✅ BACnet-Pakete erkennen (Port-basiert)
- ✅ Grundlegende Statistiken

#### Was NICHT funktioniert:
- ❌ Detaillierte BACnet-Service-Analyse
- ❌ Object Type Erkennung
- ❌ Property Identifier
- ❌ Vollständige Vendor-Informationen

Im Log erscheint:
```
⚠️  HINWEIS: TShark (Wireshark) nicht gefunden
    → Fallback auf SharpPcap (eingeschränkte BACnet-Unterstützung)
```

---

## In der Anwendung

### Status-Button "ℹ️ Wireshark"

Klicken Sie auf den Button in der Toolbar, um:

**MIT Wireshark:**
```
✅ Wireshark/TShark ist installiert!

Die Anwendung nutzt TShark für vollständige BACnet-Analyse:
• Alle BACnet-Services (ReadProperty, WriteProperty, etc.)
• Object Types und Instance Numbers
• Property Identifiers
• Vendor-Informationen

Keine weiteren Schritte erforderlich.
```

**OHNE Wireshark:**
```
⚠️ Wireshark/TShark ist NICHT installiert!

Aktuell wird SharpPcap mit eingeschränkter BACnet-Unterstützung verwendet.

Für vollständige BACnet-Analyse:
1. Wireshark herunterladen und installieren
   → https://www.wireshark.org/download.html

2. TShark wird automatisch mit Wireshark installiert

3. Anwendung neu starten

Möchten Sie die Wireshark-Download-Seite öffnen?
[Ja] [Nein]
```

---

## Typische Anwendungsfälle

### ✅ Ich habe Wireshark installiert

```bash
# Starten Sie die Anwendung
dotnet run --project src/BACnetAna.UI

# Oder in Visual Studio: F5

# Log zeigt:
✅ TShark-Parser aktiviert

# PCAP-Datei öffnen
Datei → PCAP/PCAPNG öffnen

# Analyse durchführen
→ Alle BACnet-Details werden automatisch extrahiert
```

### ⚠️ Ich habe Wireshark NICHT installiert

```bash
# Starten Sie die Anwendung
dotnet run --project src/BACnetAna.UI

# Log zeigt:
⚠️  HINWEIS: TShark (Wireshark) nicht gefunden
    → Fallback auf SharpPcap

# PCAP-Datei öffnen funktioniert
→ Aber BACnet-Details sind eingeschränkt

# Zum Installieren:
Klick auf "ℹ️ Wireshark" Button → "Ja" → Download-Seite öffnet sich
```

---

## FAQ

### Q: Muss ich Wireshark öffnen?
**A:** Nein! Die Anwendung nutzt nur TShark (CLI-Tool), das im Hintergrund läuft.

### Q: Wo ist TShark installiert?
**A:** Standardpfade:
- `C:\Program Files\Wireshark\tshark.exe`
- `C:\Program Files (x86)\Wireshark\tshark.exe`

### Q: Die Anwendung findet TShark nicht?
**A:**
1. Wireshark neu installieren
2. Anwendung neu starten
3. Falls weiterhin Probleme: Button "ℹ️ Wireshark" klicken

### Q: Kann ich einen benutzerdefinierten TShark-Pfad angeben?
**A:** Ja, im Code:
```csharp
var parser = new TSharkBACnetParser(@"C:\Custom\Path\tshark.exe");
```

### Q: Funktioniert die Anwendung offline?
**A:** Ja! TShark/Wireshark muss nur einmal installiert werden, danach keine Internet-Verbindung nötig.

### Q: Welche Wireshark-Version wird benötigt?
**A:** Wireshark 2.0 oder höher (empfohlen: neueste Version)

---

## Empfehlung

**Installieren Sie Wireshark für die beste Erfahrung!**

- 📥 Download: https://www.wireshark.org/download.html
- ⏱️ Installationszeit: ~2 Minuten
- 💾 Speicherplatz: ~150 MB
- ✅ Einmalige Installation
- 🚀 Volle BACnet-Power!

---

## Support

Bei Problemen:
1. Klicken Sie auf "ℹ️ Wireshark" Button für Status-Info
2. Prüfen Sie das Log in der Anwendung
3. Überprüfen Sie `tshark --version` in PowerShell
