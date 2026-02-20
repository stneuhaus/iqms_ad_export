"""
Batch Enrichment für gesplittete CSV-Dateien
Verarbeitet alle CSV-Dateien aus exports/splitted und enriched sie mit AD User-Daten.
"""

import sys
import os
from pathlib import Path
from datetime import datetime
import subprocess

# Parent-Verzeichnis zum Python-Path hinzufügen, um enrich_csv_with_users zu importieren
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

from enrich_csv_with_users import process_csv


class ProcessingStats:
    """Sammelt Statistiken über die Verarbeitung."""
    
    def __init__(self):
        self.processed_files = []
        self.skipped_files = []
        self.failed_files = []
        self.total_users = 0
        self.groups_not_found = []
        self.groups_found = {}
    

def process_single_file(input_file, output_file, stats):
    """
    Verarbeitet eine einzelne CSV-Datei.
    
    Args:
        input_file: Pfad zur Input-Datei
        output_file: Pfad zur Output-Datei
        stats: ProcessingStats Objekt zum Sammeln von Statistiken
        
    Returns:
        True bei Erfolg, False bei Fehler
    """
    print(f"\n{'='*80}")
    print(f"Verarbeite: {input_file.name}")
    print(f"{'='*80}")
    
    try:
        # Temporäres Import des enrich_csv_with_users Moduls
        import csv
        
        # CSV lesen
        with open(input_file, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            input_rows = list(reader)
        
        # Eindeutige AD Groups sammeln
        unique_groups = sorted(set(row['AD Security Group'] for row in input_rows))
        
        # Mit der bestehenden process_csv Funktion verarbeiten
        # Diese Funktion schreibt bereits die Output-Datei
        from enrich_csv_with_users import get_ad_group_members
        
        # Gruppen abfragen und Statistiken sammeln
        group_members_cache = {}
        
        for idx, group_name in enumerate(unique_groups, 1):
            print(f"[{idx:4d}/{len(unique_groups)}] {group_name}")
            members = get_ad_group_members(group_name)
            group_members_cache[group_name] = members
            
            if members:
                print(f"            → {len(members)} Mitglied(er) gefunden")
                stats.groups_found[group_name] = len(members)
                stats.total_users += len(members)
            else:
                print(f"            → Keine Mitglieder oder Gruppe nicht gefunden")
                if group_name not in stats.groups_not_found:
                    stats.groups_not_found.append(group_name)
        
        # Erweiterte CSV schreiben
        output_rows = []
        for row in input_rows:
            group_name = row['AD Security Group']
            members = group_members_cache.get(group_name, [])
            
            if members:
                for member in members:
                    new_row = {
                        'persona': row['persona'],
                        'AD Security Group': row['AD Security Group'],
                        'DocUnit': row['DocUnit'],
                        'User': member.get('User', ''),
                        'Alias': member.get('Alias', ''),
                        'User Status': member.get('User Status', 'Unknown')
                    }
                    output_rows.append(new_row)
            else:
                new_row = {
                    'persona': row['persona'],
                    'AD Security Group': row['AD Security Group'],
                    'DocUnit': row['DocUnit'],
                    'User': '',
                    'Alias': '',
                    'User Status': 'No Members'
                }
                output_rows.append(new_row)
        
        # Ausgabedatei schreiben
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
            fieldnames = ['persona', 'AD Security Group', 'DocUnit', 'User', 'Alias', 'User Status']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(output_rows)
        
        print(f"\n✓ Erfolgreich verarbeitet: {len(output_rows)} Zeilen geschrieben")
        stats.processed_files.append(input_file.name)
        return True
        
    except Exception as e:
        print(f"\n✗ Fehler bei der Verarbeitung: {e}")
        stats.failed_files.append((input_file.name, str(e)))
        return False


def generate_report(stats, report_file):
    """
    Generiert einen Markdown-Report über die Verarbeitung.
    
    Args:
        stats: ProcessingStats Objekt mit gesammelten Statistiken
        report_file: Pfad zur Report-Datei
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = f"""# Batch Enrichment Report

**Zeitstempel:** {timestamp}

## Zusammenfassung

- **Verarbeitete Dateien:** {len(stats.processed_files)}
- **Übersprungene Dateien:** {len(stats.skipped_files)}
- **Fehlgeschlagene Dateien:** {len(stats.failed_files)}
- **Gesamt gefundene User:** {stats.total_users}
- **AD-Gruppen ohne Mitglieder:** {len(stats.groups_not_found)}

## Verarbeitete Dateien

"""
    
    if stats.processed_files:
        for filename in stats.processed_files:
            report += f"- ✓ {filename}\n"
    else:
        report += "*Keine Dateien verarbeitet*\n"
    
    report += "\n## Übersprungene Dateien\n\n"
    
    if stats.skipped_files:
        for filename in stats.skipped_files:
            report += f"- ⊘ {filename} (bereits vorhanden)\n"
    else:
        report += "*Keine Dateien übersprungen*\n"
    
    report += "\n## Fehlgeschlagene Dateien\n\n"
    
    if stats.failed_files:
        for filename, error in stats.failed_files:
            report += f"- ✗ {filename}\n"
            report += f"  - Fehler: `{error}`\n"
    else:
        report += "*Keine Fehler*\n"
    
    report += "\n## AD-Gruppen Statistik\n\n"
    report += f"**Gesamt verschiedene Gruppen:** {len(stats.groups_found) + len(stats.groups_not_found)}\n\n"
    
    if stats.groups_found:
        report += "### Gruppen mit Mitgliedern\n\n"
        report += "| AD Security Group | Anzahl User |\n"
        report += "|-------------------|-------------|\n"
        for group, count in sorted(stats.groups_found.items(), key=lambda x: x[1], reverse=True):
            report += f"| {group} | {count} |\n"
    
    if stats.groups_not_found:
        report += "\n### Gruppen ohne Mitglieder / nicht gefunden\n\n"
        for group in sorted(stats.groups_not_found):
            report += f"- ⚠ {group}\n"
    
    report += "\n---\n*Generiert automatisch durch batch_enrich.py*\n"
    
    # Report in Datei schreiben
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    return report


def main():
    """Hauptfunktion für Batch-Verarbeitung."""
    
    # Pfade relativ zum Projekt-Root
    project_root = Path(__file__).parent.parent
    input_dir = project_root / "exports" / "splitted"
    output_dir = project_root / "exports" / "enriched"
    report_file = project_root / "exports" / "enrichment_report.md"
    
    # Output-Verzeichnis erstellen
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*80}")
    print(f"BATCH ENRICHMENT - CSV-Dateien mit AD User-Daten anreichern")
    print(f"{'='*80}\n")
    print(f"Input-Verzeichnis:  {input_dir}")
    print(f"Output-Verzeichnis: {output_dir}")
    print(f"Report-Datei:       {report_file}\n")
    
    # Prüfen ob Input-Verzeichnis existiert
    if not input_dir.exists():
        print(f"✗ Fehler: Input-Verzeichnis '{input_dir}' nicht gefunden!")
        sys.exit(1)
    
    # Alle CSV-Dateien im Input-Verzeichnis finden
    csv_files = sorted(input_dir.glob("*.csv"))
    
    if not csv_files:
        print(f"✗ Keine CSV-Dateien in '{input_dir}' gefunden!")
        sys.exit(1)
    
    print(f"✓ {len(csv_files)} CSV-Datei(en) gefunden\n")
    
    # Statistiken initialisieren
    stats = ProcessingStats()
    
    # Jede Datei verarbeiten
    for csv_file in csv_files:
        output_file = output_dir / csv_file.name
        
        # Prüfen ob Output-Datei bereits existiert
        if output_file.exists():
            print(f"\n⊘ Überspringe: {csv_file.name} (bereits vorhanden)")
            stats.skipped_files.append(csv_file.name)
            continue
        
        # Datei verarbeiten
        process_single_file(csv_file, output_file, stats)
    
    # Report generieren
    print(f"\n{'='*80}")
    print(f"REPORT GENERIEREN")
    print(f"{'='*80}\n")
    
    report_text = generate_report(stats, report_file)
    
    # Report auch in Konsole ausgeben
    print(report_text)
    
    print(f"\n✓ Report gespeichert: {report_file}")
    
    # Zusammenfassung
    print(f"\n{'='*80}")
    print(f"BATCH ENRICHMENT ABGESCHLOSSEN")
    print(f"{'='*80}")
    print(f"  Verarbeitet:   {len(stats.processed_files):4d}")
    print(f"  Übersprungen:  {len(stats.skipped_files):4d}")
    print(f"  Fehlgeschlagen: {len(stats.failed_files):4d}")
    print(f"  Gesamt User:   {stats.total_users:4d}")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
