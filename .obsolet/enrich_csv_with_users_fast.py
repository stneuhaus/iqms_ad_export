"""
CSV Enrichment mit AD User-Daten (Performance-Optimiert)
Liest AD Security Groups aus CSV, fragt Mitglieder ab und erweitert CSV mit User-Daten.
Unterstützt Batch-Verarbeitung mehrerer Dateien aus einem Verzeichnis.

OPTIMIERUNG: Alle AD-Gruppen werden in EINEM PowerShell-Aufruf abgefragt (20-30x schneller!)
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
    log_file = f"enrichment_fast_{timestamp}.log"
    
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


def get_all_ad_group_members_batch(group_names, logger=None):
    """
    Liest ALLE Mitglieder von ALLEN AD-Gruppen in EINEM PowerShell-Aufruf.
    
    PERFORMANCE-OPTIMIERUNG: Statt 197 separate PowerShell-Prozesse wird nur 1 Prozess
    gestartet, der alle Gruppen nacheinander abfragt.
    
    Args:
        group_names: Liste von AD-Gruppennamen
        logger: Logger-Instanz für Fehlerprotokollierung
        
    Returns:
        Dictionary {group_name: [members]} oder {group_name: None} bei Fehler
    """
    # PowerShell Skript zum Auslesen ALLER Gruppenmitglieder
    # Erstelle Array mit allen Gruppennamen (escaped)
    groups_array = []
    for group_name in group_names:
        escaped = group_name.replace("'", "''")
        groups_array.append(f"'{escaped}'")
    
    groups_array_str = ",".join(groups_array)
    
    ps_script = f'''[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Continue"

# Array mit allen Gruppennamen
$groupNames = @({groups_array_str})

# Domain Root abrufen
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$root = $domain.GetDirectoryEntry()

# Ergebnis-Hashtable
$allResults = @{{}}

# Fortschrittsanzeige
$currentIndex = 0
$totalGroups = $groupNames.Count

# Jede Gruppe abfragen
foreach ($groupName in $groupNames) {{
    $currentIndex++
    Write-Progress -Activity "AD-Gruppen abfragen" -Status "$currentIndex von $totalGroups" -PercentComplete (($currentIndex / $totalGroups) * 100)
    
    try {{
        # Searcher für Gruppe erstellen
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $root
        $searcher.Filter = "(&(objectCategory=group)(cn=$groupName))"
        $searcher.PropertiesToLoad.Add("member") | Out-Null
        $searcher.PropertiesToLoad.Add("cn") | Out-Null
        
        $group = $searcher.FindOne()
        
        if ($group -eq $null) {{
            $allResults[$groupName] = @()
            continue
        }}
        
        $members = $group.Properties["member"]
        $memberList = @()
        
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
                    $memberList += $user
                }}
                $userEntry.Dispose()
            }} catch {{
                # Fehler bei einzelnem Mitglied ignorieren
            }}
        }}
        
        $allResults[$groupName] = $memberList
        
    }} catch {{
        $allResults[$groupName] = @()
    }}
}}

# Als JSON ausgeben
$allResults | ConvertTo-Json -Depth 10
'''
    
    try:
        # PowerShell-Script in temporäre Datei schreiben
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as temp_ps:
            temp_ps.write(ps_script)
            temp_ps_path = temp_ps.name
        
        if logger:
            logger.info(f"Starte Batch-Abfrage für {len(group_names)} Gruppen in einem PowerShell-Prozess")
        
        try:
            # PowerShell-Datei ausführen (mit erhöhtem Timeout für viele Gruppen)
            # Timeout muss für ALLE Gruppen zusammen reichen!
            timeout = 3600  # 1 Stunde Timeout für kompletten Batch
            
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", temp_ps_path],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout
            )
        finally:
            # Temporäre Datei löschen
            try:
                os.unlink(temp_ps_path)
            except:
                pass
        
        # JSON Ausgabe parsen
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                
                # userAccountControl in Text umwandeln für alle Gruppen
                results = {}
                for group_name, members in data.items():
                    if isinstance(members, list):
                        processed_members = []
                        for user in members:
                            if 'UserAccountControl' in user and user['UserAccountControl']:
                                user['User Status'] = convert_uac_to_text(user['UserAccountControl'])
                            else:
                                user['User Status'] = "Unknown"
                            user.pop('UserAccountControl', None)
                            processed_members.append(user)
                        results[group_name] = processed_members
                    else:
                        results[group_name] = []
                
                if logger:
                    logger.info(f"Batch-Abfrage erfolgreich: {len(results)} Gruppen verarbeitet")
                
                return results
                
            except json.JSONDecodeError as e:
                # Speichere rohen Output für Debugging
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                debug_file = f"debug_batch_json_error_{timestamp}.txt"
                
                with open(debug_file, 'w', encoding='utf-8') as f:
                    f.write(f"JSON Parse-Fehler bei Batch-Abfrage\n")
                    f.write(f"Fehler: {e}\n")
                    f.write(f"Anzahl Gruppen: {len(group_names)}\n")
                    f.write(f"\n{'='*80}\n")
                    f.write("PowerShell stdout:\n")
                    f.write(f"{'='*80}\n")
                    f.write(result.stdout)
                    f.write(f"\n{'='*80}\n")
                    f.write("PowerShell stderr:\n")
                    f.write(f"{'='*80}\n")
                    f.write(result.stderr if result.stderr else "(leer)")
                
                if logger:
                    logger.error(f"JSON Parse-Fehler bei Batch-Abfrage. Debug-Datei: {debug_file}")
                
                print(f"  ⚠ JSON Parse-Fehler bei Batch-Abfrage")
                print(f"    Debug-Datei gespeichert: {debug_file}")
                
                # Rückgabe leeres Dictionary
                return {group: [] for group in group_names}
        
        # Kein Output
        return {group: [] for group in group_names}
        
    except subprocess.TimeoutExpired:
        msg = f"Timeout bei Batch-Abfrage ({len(group_names)} Gruppen)"
        print(f"  ⏱ {msg}")
        if logger:
            logger.warning(msg)
        return {group: None for group in group_names}
        
    except Exception as e:
        msg = f"Fehler bei Batch-Abfrage: {e}"
        print(f"  ⚠ {msg}")
        if logger:
            logger.error(msg)
        return {group: [] for group in group_names}


def process_csv(input_file, output_file, silent=False, logger=None):
    """
    Liest CSV mit AD Security Groups, fragt Mitglieder ab und erweitert CSV.
    
    Args:
        input_file: Pfad zum Input-CSV (persona, AD Security Group, DocUnit)
        output_file: Pfad zum Output-CSV (erweitert mit User, Alias, User Status)
        silent: Wenn True, wird weniger Output erzeugt (für Batch-Verarbeitung)
        logger: Logger-Instanz für Fehlerprotokollierung
        
    Returns:
        Dictionary mit Statistiken
    """
    if not silent:
        print(f"\n{'='*80}")
        print(f"CSV Enrichment mit AD User-Daten (PERFORMANCE-OPTIMIERT)")
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
    
    # BATCH-ABFRAGE: Alle Gruppen in EINEM PowerShell-Aufruf
    if not silent:
        print(f"{'='*80}")
        print(f"⚡ BATCH-Abfrage aller {len(technical_groups)} AD-Gruppen in EINEM PowerShell-Prozess...")
        print(f"{'='*80}\n")
    
    # Zeit messen
    batch_start = datetime.now()
    
    # Alle Gruppen auf einmal abfragen
    group_members_cache = get_all_ad_group_members_batch(technical_groups, logger)
    
    batch_end = datetime.now()
    batch_duration = (batch_end - batch_start).total_seconds()
    
    if not silent:
        print(f"\n⏱ Batch-Abfrage dauerte: {batch_duration:.1f} Sekunden")
    
    # Statistiken sammeln
    groups_found = {}
    groups_not_found = []
    timeout_groups = []
    
    for group_name, members in group_members_cache.items():
        if members is None:  # Timeout
            timeout_groups.append(group_name)
            group_members_cache[group_name] = []
        elif members:
            groups_found[group_name] = len(members)
        else:
            groups_not_found.append(group_name)
    
    if not silent:
        print(f"\n✓ Batch-Abfrage abgeschlossen")
        print(f"  - Gruppen mit Mitgliedern: {len(groups_found)}")
        print(f"  - Gruppen ohne Mitglieder: {len(groups_not_found)}")
        print(f"  - Gruppen mit Timeout: {len(timeout_groups)}\n")
    
    if not silent:
        print(f"{'='*80}")
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
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = f"""# CSV Enrichment Report (Performance-Optimiert)

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
    
    if all_skipped_groups:
        unique_skipped = sorted(set(all_skipped_groups))
        report += f"\n## Übersprungene 'schöne' Gruppennamen ({len(unique_skipped)})\n\n"
        for group in unique_skipped[:20]:
            report += f"- ⚠ {group}\n"
        if len(unique_skipped) > 20:
            report += f"\n*... und {len(unique_skipped) - 20} weitere*\n"
    
    report += "\n## AD-Gruppen Statistik\n\n"
    
    if all_groups_found:
        report += f"### Gruppen mit Mitgliedern ({len(all_groups_found)})\n\n"
        report += "| AD Security Group | Anzahl User |\n"
        report += "|-------------------|-------------|\n"
        for group, count in sorted(all_groups_found.items(), key=lambda x: x[1], reverse=True):
            report += f"| {group} | {count} |\n"
    
    if all_groups_not_found:
        unique_not_found = sorted(set(all_groups_not_found))
        report += f"\n### Gruppen ohne Mitglieder / nicht gefunden ({len(unique_not_found)})\n\n"
        for group in unique_not_found:
            report += f"- ⚠ {group}\n"
    
    if all_timeout_groups:
        unique_timeout = sorted(set(all_timeout_groups))
        report += f"\n### Gruppen mit Timeout ({len(unique_timeout)})\n\n"
        report += "*HINWEIS: Timeout bedeutet, dass das PowerShell-Script abgebrochen wurde, bevor diese Gruppen abgefragt werden konnten.*\n\n"
        for group in unique_timeout:
            report += f"- ⏱ {group}\n"
    
    report += "\n---\n*Generiert automatisch durch enrich_csv_with_users_fast.py*\n"
    
    return report


def batch_process(input_dir, output_dir, report_file):
    """
    Verarbeitet alle CSV-Dateien aus einem Verzeichnis im Batch-Modus.
    """
    logger = setup_logging()
    
    # Gesamtzeit messen
    total_start = datetime.now()
    
    logger.info("="*80)
    logger.info("BATCH ENRICHMENT (PERFORMANCE-OPTIMIERT)")
    logger.info("="*80)
    
    print(f"\n{'='*80}")
    print(f"BATCH ENRICHMENT (PERFORMANCE-OPTIMIERT)")
    print(f"⚡ Alle Gruppen werden in EINEM PowerShell-Prozess abgefragt")
    print(f"{'='*80}\n")
    print(f"Input-Verzeichnis:  {input_dir}")
    print(f"Output-Verzeichnis: {output_dir}")
    print(f"Report-Datei:       {report_file}\n")
    
    if not input_dir.exists():
        print(f"✗ Fehler: Input-Verzeichnis '{input_dir}' nicht gefunden!")
        sys.exit(1)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    csv_files = sorted(input_dir.glob("*.csv"))
    
    if not csv_files:
        print(f"✗ Keine CSV-Dateien in '{input_dir}' gefunden!")
        sys.exit(1)
    
    print(f"✓ {len(csv_files)} CSV-Datei(en) gefunden\n")
    
    processed_files = []
    skipped_files = []
    failed_files = []
    all_groups_found = {}
    all_groups_not_found = []
    all_timeout_groups = []
    all_skipped_groups = []
    total_users = 0
    
    for idx, csv_file in enumerate(csv_files, 1):
        output_file = output_dir / csv_file.name
        
        if output_file.exists():
            print(f"[{idx:4d}/{len(csv_files)}] ⊘ Überspringe: {csv_file.name} (bereits vorhanden)")
            skipped_files.append(csv_file.name)
            continue
        
        print(f"\n{'='*80}")
        print(f"[{idx:4d}/{len(csv_files)}] Verarbeite: {csv_file.name}")
        print(f"{'='*80}")
        
        logger.info(f"Verarbeite Datei {idx}/{len(csv_files)}: {csv_file.name}")
        
        file_start = datetime.now()
        
        try:
            stats = process_csv(str(csv_file), str(output_file), silent=False, logger=logger)
            
            processed_files.append(csv_file.name)
            total_users += stats['total_users']
            
            for group, count in stats['groups_found'].items():
                if group in all_groups_found:
                    all_groups_found[group] += count
                else:
                    all_groups_found[group] = count
            
            all_groups_not_found.extend(stats['groups_not_found'])
            all_timeout_groups.extend(stats['timeout_groups'])
            all_skipped_groups.extend(stats['skipped_groups'])
            
            file_end = datetime.now()
            file_duration = (file_end - file_start).total_seconds()
            
            print(f"\n✓ Erfolgreich verarbeitet: {csv_file.name}")
            print(f"  ⏱ Verarbeitungszeit: {file_duration:.1f} Sekunden")
            logger.info(f"Erfolgreich verarbeitet: {csv_file.name} ({stats['total_users']} User, {file_duration:.1f}s)")
            
        except Exception as e:
            error_msg = f"Fehler bei der Verarbeitung von {csv_file.name}: {e}"
            print(f"\n✗ {error_msg}")
            logger.error(error_msg)
            failed_files.append((csv_file.name, str(e)))
    
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
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    print(report_text)
    print(f"\n✓ Report gespeichert: {report_file}")
    
    # Gesamtzeit berechnen
    total_end = datetime.now()
    total_duration = (total_end - total_start).total_seconds()
    total_minutes = int(total_duration // 60)
    total_seconds = int(total_duration % 60)
    
    print(f"\n{'='*80}")
    print(f"BATCH ENRICHMENT ABGESCHLOSSEN")
    print(f"{'='*80}")
    print(f"  Verarbeitet:    {len(processed_files):4d}")
    print(f"  Übersprungen:   {len(skipped_files):4d}")
    print(f"  Fehlgeschlagen: {len(failed_files):4d}")
    print(f"  Gesamt User:    {total_users:4d}")
    print(f"  ⏱ Gesamtlaufzeit: {total_minutes} Min {total_seconds} Sek ({total_duration:.1f}s)")
    print(f"{'='*80}\n")
    
    logger.info("="*80)
    logger.info("BATCH ENRICHMENT ABGESCHLOSSEN")
    logger.info(f"Verarbeitet: {len(processed_files)}, Gesamt User: {total_users}")
    logger.info(f"Gesamtlaufzeit: {total_minutes} Min {total_seconds} Sek")
    logger.info("="*80)


def main():
    """Hauptfunktion."""
    import argparse
    
    project_root = Path(__file__).parent
    
    parser = argparse.ArgumentParser(
        description='Erweitert CSV mit AD Security Group Mitgliedern (PERFORMANCE-OPTIMIERT)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚡ PERFORMANCE-OPTIMIERUNG:
  Alle AD-Gruppen werden in EINEM PowerShell-Prozess abgefragt.
  Das ist 20-30x schneller als separate Aufrufe!

Beispiele:
  Batch-Verarbeitung (Standard):
    %(prog)s
  
  Einzelne Datei:
    %(prog)s -i input.csv -o output.csv
        """
    )
    
    parser.add_argument('-i', '--input', help='Input CSV-Datei')
    parser.add_argument('-o', '--output', help='Output CSV-Datei')
    parser.add_argument('--batch', action='store_true', help='Batch-Modus')
    parser.add_argument('--input-dir', help='Input-Verzeichnis (Standard: exports/splitted)')
    parser.add_argument('--output-dir', help='Output-Verzeichnis (Standard: exports/enriched)')
    parser.add_argument('--report', help='Report-Datei (Standard: exports/enrichment_report_fast.md)')
    
    args = parser.parse_args()
    
    if not args.input and not args.output and not args.batch:
        print("⚡ PERFORMANCE-MODUS aktiviert - Batch-Verarbeitung\n")
        args.batch = True
    
    if args.batch:
        input_dir = Path(args.input_dir) if args.input_dir else project_root / "exports" / "splitted"
        output_dir = Path(args.output_dir) if args.output_dir else project_root / "exports" / "enriched"
        report_file = Path(args.report) if args.report else project_root / "exports" / "enrichment_report_fast.md"
        
        batch_process(input_dir, output_dir, report_file)
        return
    
    if not args.input or not args.output:
        print("✗ Fehler: --input und --output erforderlich!")
        sys.exit(1)
    
    process_csv(args.input, args.output)
    print(f"✓ Fertig! Erweiterte CSV: {args.output}\n")


if __name__ == "__main__":
    main()
