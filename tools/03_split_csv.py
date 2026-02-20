"""
CSV Splitter - Teilt große CSV-Dateien in kleinere Chunks auf
"""

import csv
import os
import sys
from pathlib import Path


def split_csv(input_file, rows_per_file=200, output_dir=None):
    """
    Teilt eine CSV-Datei in mehrere kleinere Dateien auf.
    
    Args:
        input_file: Pfad zur Input-CSV-Datei
        rows_per_file: Anzahl der Datenzeilen pro Output-Datei (Standard: 200)
        output_dir: Verzeichnis für Output-Dateien (Standard: gleiches Verzeichnis wie Input)
    """
    # Prüfen ob Datei existiert
    if not os.path.exists(input_file):
        print(f"✗ Fehler: Datei '{input_file}' nicht gefunden!")
        sys.exit(1)
    
    # Basis-Dateiname ermitteln
    basename = os.path.basename(input_file)
    name_without_ext = os.path.splitext(basename)[0]
    extension = os.path.splitext(basename)[1]
    
    # Output-Verzeichnis festlegen
    if output_dir is None:
        output_dir = os.path.dirname(input_file)
    
    # Output-Verzeichnis erstellen falls nicht vorhanden
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\n{'='*80}")
    print(f"CSV Splitter")
    print(f"{'='*80}\n")
    print(f"Input-Datei:      {input_file}")
    print(f"Output-Verzeichnis: {output_dir}")
    print(f"Zeilen pro Datei:  {rows_per_file}")
    print(f"Output-Muster:     {name_without_ext}_XX{extension}\n")
    
    # CSV einlesen
    try:
        with open(input_file, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames
            all_rows = list(reader)
    except Exception as e:
        print(f"✗ Fehler beim Lesen der CSV: {e}")
        sys.exit(1)
    
    total_rows = len(all_rows)
    num_files = (total_rows + rows_per_file - 1) // rows_per_file  # Aufrunden
    
    print(f"✓ {total_rows} Datenzeilen eingelesen")
    print(f"✓ Wird aufgeteilt in {num_files} Datei(en)\n")
    print(f"{'='*80}")
    print(f"Erstelle Split-Dateien...")
    print(f"{'='*80}\n")
    
    # Dateien aufteilen
    created_files = []
    
    for file_num in range(num_files):
        # Dateiname mit zweistelligem Counter
        output_filename = f"{name_without_ext}_{file_num+1:02d}{extension}"
        output_path = os.path.join(output_dir, output_filename)
        
        # Start- und End-Index für diese Datei
        start_idx = file_num * rows_per_file
        end_idx = min(start_idx + rows_per_file, total_rows)
        rows_to_write = all_rows[start_idx:end_idx]
        
        # CSV-Datei schreiben
        try:
            with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=header)
                writer.writeheader()
                writer.writerows(rows_to_write)
            
            created_files.append(output_filename)
            print(f"✓ [{file_num+1:2d}/{num_files}] {output_filename:40s} ({len(rows_to_write):4d} Zeilen)")
            
        except Exception as e:
            print(f"✗ Fehler beim Schreiben von '{output_filename}': {e}")
    
    # Zusammenfassung
    print(f"\n{'='*80}")
    print(f"Statistik:")
    print(f"{'='*80}")
    print(f"  Gesamt Datenzeilen:     {total_rows:6d}")
    print(f"  Zeilen pro Datei:       {rows_per_file:6d}")
    print(f"  Erstellte Dateien:      {len(created_files):6d}")
    print(f"  Original-Datei:         unverändert")
    print(f"{'='*80}\n")
    
    print(f"✓ Fertig! {len(created_files)} Dateien erstellt.\n")
    
    return created_files


def main():
    """Hauptfunktion."""
    # Pfade relativ zum Projekt-Root definieren
    project_root = Path(__file__).parent.parent  # Eine Ebene höher als tools/
    
    # Standardwerte setzen
    default_input = project_root / "exports" / "persona_ad_sg_mapping.csv"
    default_output = project_root / "exports" / "splitted"
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Teilt CSV-Datei in kleinere Dateien auf',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  %(prog)s -i data.csv
  %(prog)s -i data.csv -r 500
  %(prog)s -i data.csv -o exports/splitted
        """
    )
    
    parser.add_argument('-i', '--input',
                       default=str(default_input),
                       help=f'Input CSV-Datei (Standard: {default_input})')
    
    parser.add_argument('-o', '--output',
                       default=str(default_output),
                       help=f'Output-Verzeichnis (Standard: {default_output})')
    
    parser.add_argument('-r', '--rows',
                       type=int,
                       default=200,
                       help='Anzahl der Datenzeilen pro Output-Datei (Standard: 200)')
    
    args = parser.parse_args()
    
    # CSV aufteilen
    split_csv(args.input, args.rows, args.output)


if __name__ == "__main__":
    main()
