#!/usr/bin/env python3
"""
Merge all enriched CSV files from exports/enriched/ into a single file.
Only the header from the first file is included.
"""

import pandas as pd
from pathlib import Path
import glob

def merge_csv_files(input_dir, output_file):
    """
    Merge all CSV files from input_dir into a single output file.
    
    Args:
        input_dir: Directory containing CSV files to merge
        output_file: Path to the output merged CSV file
    """
    # Get project root (parent.parent since script is in tools/)
    project_root = Path(__file__).parent.parent
    input_path = project_root / input_dir
    output_path = project_root / output_file
    
    # Find all CSV files in the directory
    csv_files = sorted(input_path.glob('*.csv'))
    
    if not csv_files:
        print(f"Keine CSV-Dateien gefunden in {input_path}")
        return
    
    print(f"Gefundene {len(csv_files)} CSV-Dateien:")
    for file in csv_files:
        print(f"  - {file.name}")
    
    # Read all CSV files and combine them
    dataframes = []
    
    for i, file in enumerate(csv_files):
        try:
            # Read CSV with utf-8-sig encoding (same as enrichment script)
            df = pd.read_csv(file, encoding='utf-8-sig')
            dataframes.append(df)
            print(f"Gelesen: {file.name} ({len(df)} Zeilen)")
        except Exception as e:
            print(f"Fehler beim Lesen von {file.name}: {e}")
    
    if not dataframes:
        print("Keine Daten zum Zusammenführen gefunden.")
        return
    
    # Concatenate all dataframes
    merged_df = pd.concat(dataframes, ignore_index=True)
    
    # Save to output file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged_df.to_csv(output_path, index=False, encoding='utf-8-sig')
    
    print(f"\n✓ Zusammengeführt: {len(merged_df)} Zeilen in {output_path.name}")
    print(f"  Ausgabedatei: {output_path}")

if __name__ == "__main__":
    # Default directories
    input_directory = "exports/enriched"
    output_file = "exports/persona_ad_sg_mapping_merged.csv"
    
    merge_csv_files(input_directory, output_file)
