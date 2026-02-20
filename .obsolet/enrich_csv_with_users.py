"""
CSV Enrichment mit AD User-Daten
Liest AD Security Groups aus CSV, fragt Mitglieder ab und erweitert CSV mit User-Daten.
Unterstützt Batch-Verarbeitung mehrerer Dateien aus einem Verzeichnis.
"""

import subprocess
import json
import csv
import sys
import tempfile
import os
import logging
from datetime import datetime
from pathlib import Path


def setup_logging():
    """
    Richtet Logging-System ein mit File und Console Handler.
    Logfile: enrichment_error.log
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"enrichment_{timestamp}.log"
    
    # Logger konfigurieren
    logger = logging.getLogger('enrichment')
    logger.setLevel(logging.DEBUG)
    
    # Verhindere doppelte Handler
    if logger.handlers:
        return logger
    
    # File Handler - detaillierte Logs
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    
    # Console Handler - nur Warnings und Errors
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"Logging initialisiert. Logfile: {log_file}")
    return logger


def is_technical_group_name(group_name):
    """
    Prüft, ob ein Gruppenname ein technischer AD-Gruppenname ist.
    Technische Namen enthalten typischerweise Punkte und/oder Unterstriche.
    z.B. ef.u.iqms_qms_internal_task_owner_bcc_ag_basel_ch01
    
    Args:
        group_name: Name der Gruppe
        
    Returns:
        True wenn technischer Name, False wenn "schöner" Name
    """
    # Technische Namen haben typischerweise Punkte und Unterstriche
    # und beginnen oft mit einem Präfix wie ef., ph., bs., etc.
    if not group_name:
        return False
    
    # Prüfe auf typische Muster technischer Namen
    has_dot = '.' in group_name
    has_underscore = '_' in group_name
    starts_with_prefix = any(group_name.lower().startswith(prefix) for prefix in ['ef.', 'ph.', 'bs.', 'md.'])
    
    # Technische Namen haben meistens Punkte UND Unterstriche ODER starten mit bekanntem Präfix
    return (has_dot and has_underscore) or starts_with_prefix


def convert_uac_to_text(uac_value):
    """
    Konvertiert userAccountControl Integer-Wert in lesbaren Text.
    
    Args:
        uac_value: Integer-Wert von userAccountControl
        
    Returns:
        String-Beschreibung des Account-Status
    """
    try:
        uac = int(uac_value)
    except (ValueError, TypeError):
        return "Unknown"
    
    # UAC Flag-Definitionen (häufigste Kombinationen)
    uac_flags = {
        512: "Enabled",
        514: "Disabled",
        544: "Enabled, Password Not Required",
        546: "Disabled, Password Not Required",
        66048: "Enabled, Password Never Expires",
        66050: "Disabled, Password Never Expires",
        66080: "Enabled, Password Never Expires, Not Required",
        66082: "Disabled, Password Never Expires, Not Required",
        262656: "Enabled, Smartcard Required",
        262658: "Disabled, Smartcard Required",
        328192: "Enabled, Smartcard Required, Password Never Expires",
        328194: "Disabled, Smartcard Required, Password Never Expires",
        532480: "Enabled, Workstation Trust Account",
        532482: "Disabled, Workstation Trust Account",
        4096: "Enabled, Workstation Trust Account (Legacy)",
        4098: "Disabled, Workstation Trust Account (Legacy)",
    }
    
    # Exakte Übereinstimmung prüfen
    if uac in uac_flags:
        return uac_flags[uac]
    
    # Bit-Flags analysieren für unbekannte Kombinationen
    flags = []
    if uac & 2:  # ADS_UF_ACCOUNTDISABLE
        flags.append("Disabled")
    else:
        flags.append("Enabled")
    
    if uac & 16:  # ADS_UF_LOCKOUT
        flags.append("Locked Out")
    if uac & 32:  # ADS_UF_PASSWD_NOTREQD
        flags.append("Password Not Required")
    if uac & 64:  # ADS_UF_PASSWD_CANT_CHANGE
        flags.append("Password Cannot Change")
    if uac & 65536:  # ADS_UF_DONT_EXPIRE_PASSWD
        flags.append("Password Never Expires")
    if uac & 262144:  # ADS_UF_SMARTCARD_REQUIRED
        flags.append("Smartcard Required")
    if uac & 4096:  # ADS_UF_WORKSTATION_TRUST_ACCOUNT
        flags.append("Workstation Trust Account")
    
    return ", ".join(flags) if flags else f"Unknown ({uac})"


def get_ad_group_members(group_name, debug=False, logger=None):
    """
    Liest alle Mitglieder einer AD-Gruppe aus via PowerShell ADSI.
    Gibt nur die 3 benötigten Attribute zurück.
    
    Args:
        group_name: Name der AD-Gruppe
        debug: Wenn True, wird Debug-Output ausgegeben
        logger: Logger-Instanz für Fehlerprotokollierung
        
    Returns:
        Liste von Dictionaries mit User, Alias, User Status
    """
    members = []
    
    # PowerShell Skript zum Auslesen der Gruppenmitglieder
    # Escape single quotes in group name
    group_name_escaped = group_name.replace("'", "''")
    
    ps_script = f'''[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"
try {{
    # Domain Root abrufen
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $root = $domain.GetDirectoryEntry()
    
    # Searcher für Gruppe erstellen
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $root
    $searcher.Filter = "(&(objectCategory=group)(cn={group_name_escaped}))"
    $searcher.PropertiesToLoad.Add("member") | Out-Null
    $searcher.PropertiesToLoad.Add("cn") | Out-Null
    
    $group = $searcher.FindOne()
    
    if ($group -eq $null) {{
        Write-Output "[]"
        exit 0
    }}
    
    $members = $group.Properties["member"]
    
    $results = @()
    foreach ($memberDN in $members) {{
        try {{
            $userEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$memberDN")
            
            # Nur User, keine Gruppen
            if ($userEntry.SchemaClassName -eq "user") {{
                $user = @{{
                    User = if ($userEntry.Properties["userPrincipalName"].Count -gt 0) {{ $userEntry.Properties["userPrincipalName"][0] }} else {{ "" }}
                    Alias = if ($userEntry.Properties["sAMAccountName"].Count -gt 0) {{ $userEntry.Properties["sAMAccountName"][0] }} else {{ "" }}
                    UserAccountControl = if ($userEntry.Properties["userAccountControl"].Count -gt 0) {{ $userEntry.Properties["userAccountControl"][0] }} else {{ "" }}
                }}
                $results += $user
            }}
            $userEntry.Dispose()
        }} catch {{
            Write-Warning "Fehler bei Mitglied $memberDN : $_"
        }}
    }}
    
    $results | ConvertTo-Json -Depth 2
    
}} catch {{
    Write-Output "[]"
    exit 0
}}
'''
    
    try:
        # PowerShell-Script in temporäre Datei schreiben
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as temp_ps:
            temp_ps.write(ps_script)
            temp_ps_path = temp_ps.name
        
        try:
            # PowerShell-Datei ausführen
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", temp_ps_path],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120 # 2 Minuten Timeout für große Gruppen
            )
        finally:
            # Temporäre Datei löschen
            try:
                os.unlink(temp_ps_path)
            except:
                pass
        
        # JSON Ausgabe parsen
        if result.stdout.strip():
            data = json.loads(result.stdout)
            
            # Einzelnes Objekt in Liste umwandeln
            if isinstance(data, dict):
                data = [data]
            
            # userAccountControl in Text umwandeln
            for user in data:
                if 'UserAccountControl' in user and user['UserAccountControl']:
                    user['User Status'] = convert_uac_to_text(user['UserAccountControl'])
                else:
                    user['User Status'] = "Unknown"
                # Entferne das numerische Feld
                user.pop('UserAccountControl', None)
            
            members = data
        
    except json.JSONDecodeError as e:
        # Speichere rohen Output für Debugging
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        debug_file = f"debug_json_error_{timestamp}.txt"
        
        error_details = []
        error_details.append(f"JSON Parse-Fehler für Gruppe: {group_name}")
        error_details.append(f"Fehler: {e}")
        error_details.append(f"Position: Zeile {e.lineno}, Spalte {e.colno}")
        
        with open(debug_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(error_details) + '\n')
            f.write(f"\n{'='*80}\n")
            f.write("PowerShell stdout:\n")
            f.write(f"{'='*80}\n")
            f.write(result.stdout)
            f.write(f"\n{'='*80}\n")
            f.write("PowerShell stderr:\n")
            f.write(f"{'='*80}\n")
            f.write(result.stderr if result.stderr else "(leer)")
            f.write(f"\n{'='*80}\n")
            
            # Versuche den Fehlerbereich zu zeigen
            lines = result.stdout.split('\n')
            if hasattr(e, 'lineno') and e.lineno and e.lineno <= len(lines):
                f.write(f"\nFehlerbereich (Zeile {e.lineno}):\n")
                f.write(f"{'='*80}\n")
                start = max(0, e.lineno - 3)
                end = min(len(lines), e.lineno + 2)
                for i in range(start, end):
                    marker = ">>> " if i == e.lineno - 1 else "    "
                    f.write(f"{marker}{i+1:4d}: {lines[i]}\n")
                    if i == e.lineno - 1 and hasattr(e, 'colno') and e.colno:
                        f.write(f"     {' ' * (e.colno + 3)}^\n")
        
        # Ins Log schreiben
        if logger:
            logger.error("=" * 80)
            for line in error_details:
                logger.error(line)
            logger.error(f"Debug-Datei gespeichert: {debug_file}")
            logger.error(f"\nPowerShell stdout:\n{result.stdout}")
            logger.error(f"\nPowerShell stderr:\n{result.stderr if result.stderr else '(leer)'}")
            logger.error("=" * 80)
        
        print(f"  ⚠ JSON Parse-Fehler bei Gruppe '{group_name}': {e}")
        print(f"    Debug-Datei gespeichert: {debug_file}")
        
        # Versuche den Inhalt teilweise zu parsen
        try:
            # Manchmal gibt es trailing commas oder ähnliches
            cleaned = result.stdout.strip().rstrip(',')
            data = json.loads(cleaned)
            print(f"    ✓ Inhalt konnte nach Bereinigung geparst werden")
            if logger:
                logger.info(f"Gruppe '{group_name}': JSON konnte nach Bereinigung geparst werden")
            if isinstance(data, dict):
                data = [data]
            for user in data:
                if 'UserAccountControl' in user and user['UserAccountControl']:
                    user['User Status'] = convert_uac_to_text(user['UserAccountControl'])
                else:
                    user['User Status'] = "Unknown"
                user.pop('UserAccountControl', None)
            members = data
        except:
            print(f"    ✗ Inhalt konnte nicht wiederhergestellt werden")
            if logger:
                logger.error(f"Gruppe '{group_name}': Inhalt konnte nicht wiederhergestellt werden")
            
    except subprocess.TimeoutExpired:
        msg = f"Timeout bei Gruppe '{group_name}'"
        print(f"  ⏱ {msg}")
        if logger:
            logger.warning(msg)
        return None  # Spezieller Rückgabewert für Timeout
    except Exception as e:
        msg = f"Fehler bei Gruppe '{group_name}': {e}"
        print(f"  ⚠ {msg}")
        if logger:
            logger.error(msg)
    
    return members


def process_csv(input_file, output_file, silent=False, logger=None):
    """
    Liest CSV mit AD Security Groups, fragt Mitglieder ab und erweitert CSV.
    
    Args:
        input_file: Pfad zum Input-CSV (persona, AD Security Group, DocUnit)
        output_file: Pfad zum Output-CSV (erweitert mit User, Alias, User Status)
        silent: Wenn True, wird weniger Output erzeugt (für Batch-Verarbeitung)
        logger: Logger-Instanz für Fehlerprotokollierung
        
    Returns:
        Dictionary mit Statistiken: {
            'total_users': int,
            'groups_without_members': int,
            'groups_found': dict,  # {group_name: member_count}
            'groups_not_found': list,
            'timeout_groups': list,
            'skipped_groups': list,
            'input_rows': int,
            'output_rows': int
        }
    """
    if not silent:
        print(f"\n{'='*80}")
        print(f"CSV Enrichment mit AD User-Daten")
        print(f"{'='*80}\n")
        print(f"Input:  {input_file}")
        print(f"Output: {output_file}\n")
    
    # CSV lesen
    try:
        with open(input_file, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            input_rows = list(reader)
    except FileNotFoundError:
        if not silent:
            print(f"✗ Fehler: Datei '{input_file}' nicht gefunden!")
        raise
    except Exception as e:
        if not silent:
            print(f"✗ Fehler beim Lesen der CSV: {e}")
        raise
    
    if not silent:
        print(f"✓ {len(input_rows)} Zeilen eingelesen")
    
    # Eindeutige AD Security Groups sammeln
    unique_groups = sorted(set(row['AD Security Group'] for row in input_rows))
    
    # Filtern: Nur technische Gruppennamen
    technical_groups = []
    skipped_groups = []
    
    for group in unique_groups:
        if is_technical_group_name(group):
            technical_groups.append(group)
        else:
            skipped_groups.append(group)
    
    if not silent:
        print(f"✓ {len(unique_groups)} eindeutige AD Security Groups gefunden")
        print(f"  - Technische Namen: {len(technical_groups)}")
        print(f"  - Übersprungene 'schöne' Namen: {len(skipped_groups)}")
        if skipped_groups:
            print(f"\n⚠ Übersprungene Gruppen (erste 10):")
            for group in skipped_groups[:10]:
                print(f"    - {group}")
            if len(skipped_groups) > 10:
                print(f"    ... und {len(skipped_groups) - 10} weitere")
        print()
    
    # Fortschrittsanzeige
    if not silent:
        print(f"{'='*80}")
        print(f"Abfrage der AD-Gruppen (das kann einige Minuten dauern)...")
        print(f"{'='*80}\n")
    
    # Dictionary zum Caching der Group-Members
    group_members_cache = {}
    groups_found = {}
    groups_not_found = []
    timeout_groups = []
    
    # Alle technischen Gruppen abfragen
    for idx, group_name in enumerate(technical_groups, 1):
        if not silent:
            print(f"[{idx:4d}/{len(technical_groups)}] {group_name}")
        
        # Debug deaktiviert für Performance
        debug = False
        members = get_ad_group_members(group_name, debug=debug, logger=logger)
        
        if members is None:  # Timeout
            if not silent:
                print(f"            ⏱ Timeout nach 120 Sekunden")
            timeout_groups.append(group_name)
            group_members_cache[group_name] = []
        elif members:
            if not silent:
                print(f"            → {len(members)} Mitglied(er) gefunden")
            groups_found[group_name] = len(members)
            group_members_cache[group_name] = members
        else:
            if not silent:
                print(f"            → Keine Mitglieder oder Gruppe nicht gefunden")
            groups_not_found.append(group_name)
            group_members_cache[group_name] = []
    
    if not silent:
        print(f"\n{'='*80}")
        print(f"Erweitere CSV-Daten...")
        print(f"{'='*80}\n")
    
    # Neue Zeilen mit User-Daten erstellen
    output_rows = []
    total_users = 0
    groups_without_members = 0
    
    for row in input_rows:
        group_name = row['AD Security Group']
        
        # Überspringe "schöne" Namen
        if not is_technical_group_name(group_name):
            continue
        
        members = group_members_cache.get(group_name, [])
        
        if members:
            # Für jedes Mitglied eine neue Zeile erstellen
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
                total_users += 1
        else:
            # Gruppe ohne Mitglieder: Zeile ohne User-Daten eintragen
            new_row = {
                'persona': row['persona'],
                'AD Security Group': row['AD Security Group'],
                'DocUnit': row['DocUnit'],
                'User': '',
                'Alias': '',
                'User Status': 'No Members'
            }
            output_rows.append(new_row)
            groups_without_members += 1
    
    # Erweiterte CSV schreiben
    try:
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
            fieldnames = ['persona', 'AD Security Group', 'DocUnit', 'User', 'Alias', 'User Status']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(output_rows)
        
        if not silent:
            print(f"✓ CSV erfolgreich erweitert und gespeichert\n")
            print(f"{'='*80}")
            print(f"Statistik:")
            print(f"{'='*80}")
            print(f"  Eingabe-Zeilen:              {len(input_rows):6d}")
            print(f"  AD Security Groups:          {len(unique_groups):6d}")
            print(f"  Gruppen ohne Mitglieder:     {groups_without_members:6d}")
            print(f"  Gefundene User:              {total_users:6d}")
            print(f"  Ausgabe-Zeilen:              {len(output_rows):6d}")
            print(f"{'='*80}\n")
        
        # Statistiken zurückgeben
        return {
            'total_users': total_users,
            'groups_without_members': groups_without_members,
            'groups_found': groups_found,
            'groups_not_found': groups_not_found,
            'timeout_groups': timeout_groups,
            'skipped_groups': skipped_groups,
            'input_rows': len(input_rows),
            'output_rows': len(output_rows)
        }
        
    except Exception as e:
        if not silent:
            print(f"✗ Fehler beim Schreiben der CSV: {e}")
        raise


def generate_report(processed_files, skipped_files, failed_files, all_groups_found, all_groups_not_found, all_timeout_groups, all_skipped_groups, total_users):
    """
    Generiert einen Markdown-Report über die Batch-Verarbeitung.
    
    Args:
        processed_files: Liste der verarbeiteten Dateinamen
        skipped_files: Liste der übersprungenen Dateinamen
        failed_files: Liste von Tuples (filename, error)
        all_groups_found: Dictionary {group_name: member_count}
        all_groups_not_found: Liste der nicht gefundenen Gruppen
        all_timeout_groups: Liste der Gruppen mit Timeout
        all_skipped_groups: Liste der übersprungenen "schönen" Gruppennamen
        total_users: Gesamtanzahl gefundener User
        
    Returns:
        String mit Markdown-Report
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = f"""# CSV Enrichment Report

**Zeitstempel:** {timestamp}

## Zusammenfassung

- **Verarbeitete Dateien:** {len(processed_files)}
- **Übersprungene Dateien:** {len(skipped_files)}
- **Fehlgeschlagene Dateien:** {len(failed_files)}
- **Gesamt gefundene User:** {total_users}
- **AD-Gruppen ohne Mitglieder:** {len(all_groups_not_found)}
- **AD-Gruppen mit Timeout:** {len(set(all_timeout_groups))}
- **Übersprungene "schöne" Gruppennamen:** {len(set(all_skipped_groups))}

## Verarbeitete Dateien

"""
    
    if processed_files:
        for filename in processed_files:
            report += f"- ✓ {filename}\n"
    else:
        report += "*Keine Dateien verarbeitet*\n"
    
    report += "\n## Übersprungene Dateien\n\n"
    
    if skipped_files:
        for filename in skipped_files:
            report += f"- ⊘ {filename} (bereits vorhanden)\n"
    else:
        report += "*Keine Dateien übersprungen*\n"
    
    report += "\n## Fehlgeschlagene Dateien\n\n"
    
    if failed_files:
        for filename, error in failed_files:
            report += f"- ✗ {filename}\n"
            report += f"  - Fehler: `{error}`\n"
    else:
        report += "*Keine Fehler*\n"
    
    # Übersprungene "schöne" Gruppennamen
    if all_skipped_groups:
        unique_skipped = sorted(set(all_skipped_groups))
        report += f"\n## Übersprungene 'schöne' Gruppennamen ({len(unique_skipped)})\n\n"
        report += "*Diese Gruppen haben kein technisches Format und wurden nicht in AD gesucht:*\n\n"
        for group in unique_skipped:
            report += f"- ⚠ {group}\n"
    
    report += "\n## AD-Gruppen Statistik\n\n"
    report += f"**Gesamt verschiedene Gruppen:** {len(all_groups_found) + len(all_groups_not_found)}\n\n"
    
    if all_groups_found:
        report += "### Gruppen mit Mitgliedern\n\n"
        report += "| AD Security Group | Anzahl User |\n"
        report += "|-------------------|-------------|\n"
        for group, count in sorted(all_groups_found.items(), key=lambda x: x[1], reverse=True):
            report += f"| {group} | {count} |\n"
    
    if all_groups_not_found:
        report += "\n### Gruppen ohne Mitglieder / nicht gefunden\n\n"
        for group in sorted(set(all_groups_not_found)):
            report += f"- ⚠ {group}\n"
    
    if all_timeout_groups:
        unique_timeout = sorted(set(all_timeout_groups))
        report += f"\n### Gruppen mit Timeout ({len(unique_timeout)})\n\n"
        report += "*Diese Gruppen haben zu lange für die Abfrage gebraucht (>120 Sekunden):*\n\n"
        for group in unique_timeout:
            report += f"- ⏱ {group}\n"
    
    report += "\n---\n*Generiert automatisch durch enrich_csv_with_users.py*\n"
    
    return report


def batch_process(input_dir, output_dir, report_file):
    """
    Verarbeitet alle CSV-Dateien aus einem Verzeichnis im Batch-Modus.
    
    Args:
        input_dir: Verzeichnis mit Input-CSV-Dateien
        output_dir: Verzeichnis für Output-CSV-Dateien
        report_file: Pfad für den Markdown-Report
    """
    # Logger initialisieren
    logger = setup_logging()
    
    logger.info("="*80)
    logger.info("BATCH ENRICHMENT - CSV-Dateien mit AD User-Daten anreichern")
    logger.info("="*80)
    logger.info(f"Input-Verzeichnis:  {input_dir}")
    logger.info(f"Output-Verzeichnis: {output_dir}")
    logger.info(f"Report-Datei:       {report_file}")
    
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
    
    # Output-Verzeichnis erstellen
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Alle CSV-Dateien im Input-Verzeichnis finden
    csv_files = sorted(input_dir.glob("*.csv"))
    
    if not csv_files:
        print(f"✗ Keine CSV-Dateien in '{input_dir}' gefunden!")
        sys.exit(1)
    
    print(f"✓ {len(csv_files)} CSV-Datei(en) gefunden\n")
    
    # Statistiken sammeln
    processed_files = []
    skipped_files = []
    failed_files = []
    all_groups_found = {}
    all_groups_not_found = []
    all_timeout_groups = []
    all_skipped_groups = []
    total_users = 0
    
    # Jede Datei verarbeiten
    for idx, csv_file in enumerate(csv_files, 1):
        output_file = output_dir / csv_file.name
        
        # Prüfen ob Output-Datei bereits existiert
        if output_file.exists():
            print(f"[{idx:4d}/{len(csv_files)}] ⊘ Überspringe: {csv_file.name} (bereits vorhanden)")
            skipped_files.append(csv_file.name)
            continue
        
        print(f"\n{'='*80}")
        print(f"[{idx:4d}/{len(csv_files)}] Verarbeite: {csv_file.name}")
        print(f"{'='*80}")
        print(f"DEBUG: Input-Datei:  {csv_file}")
        print(f"DEBUG: Output-Datei: {output_file}")
        
        logger.info(f"Verarbeite Datei {idx}/{len(csv_files)}: {csv_file.name}")
        
        try:
            # Datei verarbeiten
            stats = process_csv(str(csv_file), str(output_file), silent=False, logger=logger)
            
            print(f"\nDEBUG: Statistiken für {csv_file.name}:")
            print(f"  - Input Zeilen: {stats['input_rows']}")
            print(f"  - Output Zeilen: {stats['output_rows']}")
            print(f"  - Gefundene User: {stats['total_users']}")
            print(f"  - Gruppen gefunden: {len(stats['groups_found'])}")
            print(f"  - Gruppen nicht gefunden: {len(stats['groups_not_found'])}")
            print(f"  - Gruppen mit Timeout: {len(stats['timeout_groups'])}")
            print(f"  - Übersprungene 'schöne' Namen: {len(stats['skipped_groups'])}")
            
            # Statistiken sammeln
            processed_files.append(csv_file.name)
            total_users += stats['total_users']
            
            # Gruppen-Statistiken zusammenführen
            for group, count in stats['groups_found'].items():
                if group in all_groups_found:
                    all_groups_found[group] += count
                else:
                    all_groups_found[group] = count
            
            all_groups_not_found.extend(stats['groups_not_found'])
            all_timeout_groups.extend(stats['timeout_groups'])
            all_skipped_groups.extend(stats['skipped_groups'])
            
            print(f"\n✓ Erfolgreich verarbeitet: {csv_file.name}")
            logger.info(f"Erfolgreich verarbeitet: {csv_file.name} ({stats['total_users']} User)")
            
        except Exception as e:
            error_msg = f"Fehler bei der Verarbeitung von {csv_file.name}: {e}"
            print(f"\n✗ {error_msg}")
            logger.error(error_msg)
            failed_files.append((csv_file.name, str(e)))
    
    # Report generieren
    print(f"\n{'='*80}")
    print(f"REPORT GENERIEREN")
    print(f"{'='*80}\n")
    
    report_text = generate_report(
        processed_files, 
        skipped_files, 
        failed_files, 
        all_groups_found, 
        all_groups_not_found,
        all_timeout_groups,
        all_skipped_groups,
        total_users
    )
    
    # Report in Datei schreiben
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    # Report auch in Konsole ausgeben
    print(report_text)
    
    print(f"\n✓ Report gespeichert: {report_file}")
    
    # Zusammenfassung
    print(f"\n{'='*80}")
    print(f"BATCH ENRICHMENT ABGESCHLOSSEN")
    print(f"{'='*80}")
    print(f"  Verarbeitet:    {len(processed_files):4d}")
    print(f"  Übersprungen:   {len(skipped_files):4d}")
    print(f"  Fehlgeschlagen: {len(failed_files):4d}")
    print(f"  Gesamt User:    {total_users:4d}")
    print(f"{'='*80}\n")
    
    # Log-Abschluss
    logger.info("="*80)
    logger.info("BATCH ENRICHMENT ABGESCHLOSSEN")
    logger.info(f"Verarbeitet: {len(processed_files)}, Übersprungen: {len(skipped_files)}, Fehlgeschlagen: {len(failed_files)}")
    logger.info(f"Gesamt User: {total_users}")
    logger.info("="*80)


def main():
    """Hauptfunktion."""
    import argparse
    
    # Pfade relativ zum Projekt-Root
    project_root = Path(__file__).parent
    
    parser = argparse.ArgumentParser(
        description='Erweitert CSV mit AD Security Group Mitgliedern',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  Einzelne Datei verarbeiten:
    %(prog)s -i persona_ad_sg_mapping.csv -o persona_users_enriched.csv
  
  Batch-Verarbeitung:
    %(prog)s --batch
        """
    )
    
    parser.add_argument('-i', '--input',
                       help='Input CSV-Datei (für Einzelverarbeitung)')
    
    parser.add_argument('-o', '--output',
                       help='Output CSV-Datei (für Einzelverarbeitung)')
    
    parser.add_argument('--batch',
                       action='store_true',
                       help='Batch-Modus: Verarbeitet alle Dateien aus exports/splitted')
    
    parser.add_argument('--input-dir',
                       help='Input-Verzeichnis für Batch-Modus (Standard: exports/splitted)')
    
    parser.add_argument('--output-dir',
                       help='Output-Verzeichnis für Batch-Modus (Standard: exports/enriched)')
    
    parser.add_argument('--report',
                       help='Report-Datei für Batch-Modus (Standard: exports/enrichment_report.md)')
    
    args = parser.parse_args()
    
    # Wenn keine Parameter angegeben wurden, standardmäßig Batch-Modus verwenden
    if not args.input and not args.output and not args.batch:
        print("Kein Parameter angegeben - verwende Batch-Modus\n")
        args.batch = True
    
    # Batch-Modus
    if args.batch:
        input_dir = Path(args.input_dir) if args.input_dir else project_root / "exports" / "splitted"
        output_dir = Path(args.output_dir) if args.output_dir else project_root / "exports" / "enriched"
        report_file = Path(args.report) if args.report else project_root / "exports" / "enrichment_report.md"
        
        batch_process(input_dir, output_dir, report_file)
        return  # Wichtig: Hier beenden, nicht weiter in die Einzelverarbeitung
    
    # Einzelverarbeitung
    if not args.input or not args.output:
        print("✗ Fehler: Für Einzelverarbeitung müssen --input und --output angegeben werden!")
        print("   Oder verwenden Sie --batch für Batch-Verarbeitung")
        sys.exit(1)
        
        # CSV verarbeiten
        process_csv(args.input, args.output)
        
        print(f"✓ Fertig! Die erweiterte CSV wurde gespeichert unter: {args.output}\n")


if __name__ == "__main__":
    main()
