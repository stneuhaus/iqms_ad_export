#!/usr/bin/env python3
"""
AD Group Technical Name Lookup Tool

Liest ein Excel-Tabellenblatt "non-Existing AD groups" mit displayName-Spalte
und ermittelt für jede Gruppe den technischen Namen (cn-Attribut) aus Active Directory.
Der technische Name wird als neue Spalte "GroupName" hinzugefügt.
"""

import pandas as pd
import subprocess
import tempfile
import json
import logging
from pathlib import Path
from datetime import datetime


def setup_logging():
    """
    Richtet Logging ein (Konsole + Datei).
    
    Returns:
        Logger-Instanz
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = Path(__file__).parent.parent / f"lookup_technical_names_{timestamp}.log"
    
    # Logger konfigurieren
    logger = logging.getLogger('lookup_technical_names')
    logger.setLevel(logging.DEBUG)
    
    # File Handler
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    
    # Console Handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    logger.info(f"Log-Datei: {log_file}")
    return logger


def get_group_cn_from_ad(display_name, logger):
    """
    Ermittelt den technischen Gruppennamen (cn) aus Active Directory.
    
    Args:
        display_name: Display Name der Gruppe
        logger: Logger-Instanz
        
    Returns:
        cn (technischer Name) als String oder None bei Fehler
    """
    # PowerShell-Script zum Suchen der Gruppe nach displayName
    ps_script = f"""
$ErrorActionPreference = 'Stop'

try {{
    # Domain Controller abrufen
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $dc = $domain.FindDomainController().Name
    
    # DirectorySearcher konfigurieren
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = "LDAP://$dc"
    
    # Filter: Suche nach displayName (mit Trim für Sicherheit)
    $displayNameTrimmed = "{display_name}".Trim()
    $displayNameEscaped = $displayNameTrimmed.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)")
    $searcher.Filter = "(&(objectClass=group)(displayName=$displayNameEscaped))"
    
    # Eigenschaften laden
    $searcher.PropertiesToLoad.Add("cn") | Out-Null
    $searcher.PropertiesToLoad.Add("displayName") | Out-Null
    $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
    
    # Suche durchführen
    $result = $searcher.FindOne()
    
    if ($result -ne $null) {{
        $cn = if ($result.Properties["cn"]) {{ $result.Properties["cn"][0] }} else {{ $null }}
        $dn = if ($result.Properties["distinguishedName"]) {{ $result.Properties["distinguishedName"][0] }} else {{ $null }}
        
        # JSON-Ausgabe
        $output = @{{
            "found" = $true
            "cn" = $cn
            "displayName" = $result.Properties["displayName"][0]
            "distinguishedName" = $dn
        }}
        
        $output | ConvertTo-Json -Depth 5 -Compress
    }} else {{
        # Gruppe nicht gefunden
        $output = @{{
            "found" = $false
            "cn" = $null
            "error" = "Gruppe nicht gefunden"
        }}
        
        $output | ConvertTo-Json -Depth 5 -Compress
    }}
}}
catch {{
    # Fehler aufgetreten
    $output = @{{
        "found" = $false
        "cn" = $null
        "error" = $_.Exception.Message
    }}
    
    $output | ConvertTo-Json -Depth 5 -Compress
}}
"""
    
    try:
        # Temporäre PowerShell-Datei erstellen
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
            temp_file = f.name
            f.write(ps_script)
        
        logger.debug(f"PowerShell-Script erstellt: {temp_file}")
        
        # PowerShell ausführen
        result = subprocess.run(
            ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', temp_file],
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8'
        )
        
        # Temporäre Datei löschen
        try:
            Path(temp_file).unlink()
        except:
            pass
        
        if result.returncode != 0:
            logger.error(f"PowerShell-Fehler für '{display_name}': {result.stderr}")
            return None
        
        # JSON parsen
        try:
            data = json.loads(result.stdout.strip())
            
            if data.get('found'):
                cn = data.get('cn')
                logger.info(f"✓ Gefunden: '{display_name}' → cn='{cn}'")
                return cn
            else:
                error = data.get('error', 'Unbekannter Fehler')
                logger.warning(f"✗ Nicht gefunden: '{display_name}' → {error}")
                return None
                
        except json.JSONDecodeError as e:
            logger.error(f"JSON-Parse-Fehler für '{display_name}': {e}")
            logger.debug(f"PowerShell-Output: {result.stdout}")
            return None
            
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout bei der Suche nach '{display_name}'")
        return None
        
    except Exception as e:
        logger.error(f"Fehler bei der Suche nach '{display_name}': {e}")
        return None


def process_excel_file(excel_file, sheet_name, logger):
    """
    Verarbeitet das Excel-File und fügt GroupName-Spalte hinzu.
    
    Args:
        excel_file: Pfad zur Excel-Datei
        sheet_name: Name des Tabellenblatts
        logger: Logger-Instanz
        
    Returns:
        True bei Erfolg, False bei Fehler
    """
    try:
        # Excel-Datei einlesen
        logger.info(f"Lese Excel-Datei: {excel_file}")
        logger.info(f"Tabellenblatt: {sheet_name}")
        
        df = pd.read_excel(excel_file, sheet_name=sheet_name)
        
        # displayName-Spalte von Leerzeichen befreien
        if 'displayName' in df.columns:
            df['displayName'] = df['displayName'].astype(str).str.strip()
        
        logger.info(f"✓ {len(df)} Zeilen eingelesen")
        logger.info(f"Spalten: {list(df.columns)}")
        
        # Prüfen ob displayName-Spalte existiert
        if 'displayName' not in df.columns:
            logger.error(f"✗ Spalte 'displayName' nicht gefunden!")
            logger.error(f"Vorhandene Spalten: {list(df.columns)}")
            return False
        
        # GroupName-Spalte hinzufügen (falls noch nicht vorhanden)
        if 'GroupName' not in df.columns:
            df['GroupName'] = None
            logger.info("Spalte 'GroupName' hinzugefügt")
        
        # Für jede Zeile den technischen Namen ermitteln
        total_rows = len(df)
        found_count = 0
        not_found_count = 0
        
        print(f"\n{'='*80}")
        print(f"AD LOOKUP - Technische Gruppennamen ermitteln")
        print(f"{'='*80}\n")
        
        for idx, row in df.iterrows():
            display_name = row['displayName']
            
            # Leere Werte überspringen
            if pd.isna(display_name) or str(display_name).strip() == '':
                logger.debug(f"[{idx+1:4d}/{total_rows}] Überspringe leere Zeile")
                continue
            
            display_name = str(display_name).strip()
            
            print(f"[{idx+1:4d}/{total_rows}] {display_name}")
            logger.info(f"[{idx+1:4d}/{total_rows}] Suche: {display_name}")
            
            # CN aus AD holen
            cn = get_group_cn_from_ad(display_name, logger)
            
            if cn:
                df.at[idx, 'GroupName'] = cn
                found_count += 1
                print(f"            → cn = '{cn}'")
            else:
                not_found_count += 1
                print(f"            → Nicht gefunden oder Fehler")
        
        # Statistik
        print(f"\n{'='*80}")
        print(f"STATISTIK")
        print(f"{'='*80}")
        print(f"  Gesamt:        {total_rows:4d}")
        print(f"  Gefunden:      {found_count:4d}")
        print(f"  Nicht gefunden:{not_found_count:4d}")
        print(f"{'='*80}\n")
        
        logger.info(f"Statistik: {found_count} gefunden, {not_found_count} nicht gefunden")
        
        # Excel-Datei zurückschreiben
        logger.info(f"Schreibe Excel-Datei zurück: {excel_file}")
        
        # Excel mit openpyxl-Engine schreiben (um existierende Sheets zu erhalten)
        with pd.ExcelWriter(excel_file, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
            df.to_excel(writer, sheet_name=sheet_name, index=False)
        
        logger.info(f"✓ Excel-Datei erfolgreich aktualisiert")
        print(f"✓ Excel-Datei aktualisiert: {excel_file}")
        
        return True
        
    except FileNotFoundError:
        logger.error(f"✗ Datei nicht gefunden: {excel_file}")
        return False
        
    except ValueError as e:
        logger.error(f"✗ Tabellenblatt '{sheet_name}' nicht gefunden: {e}")
        return False
        
    except Exception as e:
        logger.error(f"✗ Fehler bei der Verarbeitung: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def main():
    """Hauptfunktion."""
    # Logger initialisieren
    logger = setup_logging()
    
    print(f"\n{'='*80}")
    print(f"AD GROUP TECHNICAL NAME LOOKUP")
    print(f"{'='*80}\n")
    
    # Pfade relativ zum Projekt-Root
    project_root = Path(__file__).parent.parent
    
    # Excel-Datei: mapping_persona_sg/ID now-Personas mapping.xlsx
    excel_file = project_root / "mapping_persona_sg" / "ID now-Personas mapping.xlsx"
    
    # Tabellenblatt-Name
    sheet_name = "non-Existing AD groups"
    
    logger.info("="*80)
    logger.info("AD GROUP TECHNICAL NAME LOOKUP")
    logger.info("="*80)
    logger.info(f"Projekt-Root: {project_root}")
    logger.info(f"Excel-Datei:  {excel_file}")
    logger.info(f"Tabellenblatt: {sheet_name}")
    
    # Prüfen ob Datei existiert
    if not excel_file.exists():
        print(f"✗ Fehler: Excel-Datei nicht gefunden!")
        print(f"  Erwartet: {excel_file}")
        print(f"\nBitte prüfen Sie, ob die Datei existiert:")
        print(f"  {excel_file}")
        logger.error(f"Excel-Datei nicht gefunden: {excel_file}")
        return 1
    
    # Excel verarbeiten
    success = process_excel_file(excel_file, sheet_name, logger)
    
    if success:
        print(f"\n✓ Verarbeitung erfolgreich abgeschlossen")
        logger.info("Verarbeitung erfolgreich abgeschlossen")
        return 0
    else:
        print(f"\n✗ Verarbeitung fehlgeschlagen (siehe Log)")
        logger.error("Verarbeitung fehlgeschlagen")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
