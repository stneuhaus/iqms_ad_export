# AD Group Export Tool

Python-Programm zum Auslesen von Benutzern einer Active Directory Gruppe unter Windows.

## Installation

1. Dependencies installieren:
```bash
pip install -r requirements.txt
```

## Verwendung

### Grundlegende Ausgabe (Konsole):
```bash
python ad_group_export.py -g "Gruppenname"
```

### Export als CSV:
```bash
python ad_group_export.py -g "IT-Abteilung" --csv benutzer.csv
```

### Export als JSON:
```bash
python ad_group_export.py -g "Marketing" --json benutzer.json
```

### Kombiniert (Konsole + CSV + JSON):
```bash
python ad_group_export.py -g "Vertrieb" --csv vertrieb.csv --json vertrieb.json
```

## Exportierte Felder

- DisplayName (Anzeigename)
- SamAccountName (Login-Name)
- Email
- Vorname
- Nachname
- Abteilung
- Telefon
- Titel
- Beschreibung
- DN (Distinguished Name)

## Voraussetzungen

- Windows Betriebssystem
- Zugriff auf Active Directory
- Python 3.x
- pywin32 Library

## Hinweise

- Das Programm muss auf einem System mit AD-Zugriff ausgeführt werden
- Der ausführende Benutzer benötigt Leserechte im Active Directory
- Gruppenname muss exakt angegeben werden (Case-sensitive)
