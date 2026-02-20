"""
CSV Enrichment mit AD User-Daten (Microsoft Graph API)
Liest AD Security Groups aus CSV, fragt Mitglieder ab und erweitert CSV mit User-Daten.
Unterstützt Batch-Verarbeitung mehrerer Dateien aus einem Verzeichnis.

MICROSOFT GRAPH API: Verwendet Azure AD / Entra ID statt on-premises PowerShell
"""

from asyncio.log import logger
import subprocess
import json
import csv
import sys
import os
import logging
import base64
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dotenv import load_dotenv
from urllib.parse import quote

# Configure stdout encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'ignore')

# Load environment variables from .env file
load_dotenv()


def get_requests_session():
    """
    Erstellt requests Session mit Proxy-Support.
    Verwendet System-Proxy-Einstellungen oder NO_PROXY aus .env.
    """
    session = requests.Session()
    
    # Check if NO_PROXY is set in .env (to bypass proxy for testing)
    no_proxy = os.getenv('NO_PROXY', '').lower()
    use_proxy = os.getenv('USE_PROXY', 'true').lower()
    
    if no_proxy == 'true' or use_proxy == 'false':
        # Disable proxy
        session.trust_env = False
        session.proxies = {
            'http': None,
            'https': None
        }
    else:
        # Use system proxy settings (default behavior)
        # requests will automatically use HTTP_PROXY and HTTPS_PROXY env vars
        session.trust_env = True
    
    return session


def setup_logging():
    """
    Richtet Logging-System ein mit File und Console Handler.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"enrichment_msgraph_{timestamp}.log"
    
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


def setup_observations_log():
    """
    Richtet Observations Log ein für Warnungen und besondere Ereignisse.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    obs_file = f"observations_{timestamp}.log"
    
    # Observations Logger
    obs_logger = logging.getLogger('observations')
    obs_logger.setLevel(logging.INFO)
    obs_logger.propagate = False  # Nicht an Parent-Logger weitergeben
    
    # Verhindere doppelte Handler
    if obs_logger.handlers:
        return obs_logger, obs_file
    
    # File Handler
    obs_handler = logging.FileHandler(obs_file, encoding='utf-8')
    obs_handler.setLevel(logging.INFO)
    obs_formatter = logging.Formatter('%(message)s')
    obs_handler.setFormatter(obs_formatter)
    
    obs_logger.addHandler(obs_handler)
    
    # Header schreiben
    obs_logger.info("="*100)
    obs_logger.info(f"OBSERVATIONS LOG - enrich_csv_with_users_msgraph.py")
    obs_logger.info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    obs_logger.info("="*100)
    obs_logger.info(f"{'Observation Description':<60} | {'userPrincipalName/Details'}")
    obs_logger.info("-"*100)
    
    return obs_logger, obs_file


def format_duration(delta) -> str:
    """Formatiert timedelta als lesbarer String."""
    total_seconds = int(delta.total_seconds())
    if total_seconds < 0:
        total_seconds = 0
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


def log_token_validity(token: str, logger=None) -> None:
    """Prüft und loggt JWT Token Gültigkeit."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            if logger:
                logger.warning("Bearer token does not look like a JWT; validity cannot be determined")
            return

        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_bytes.decode("utf-8"))

        exp = payload.get("exp")
        if not exp:
            if logger:
                logger.warning("Bearer token does not include 'exp' claim; validity cannot be determined")
            return

        exp_time = datetime.fromtimestamp(int(exp), tz=timezone.utc)
        now = datetime.now(timezone.utc)
        remaining = exp_time - now

        if remaining.total_seconds() <= 0:
            msg = f"Bearer token expired at {exp_time.isoformat()}"
            if logger:
                logger.warning(msg)
            print(f"⚠ {msg}")
        else:
            msg = f"Bearer token valid until {exp_time.isoformat()} (remaining {format_duration(remaining)})"
            if logger:
                logger.info(msg)
            print(f"✓ {msg}")
    except Exception as e:
        if logger:
            logger.warning(f"Unable to determine bearer token validity: {e}")


def is_technical_group_name(group_name):
    """
    Prüft, ob ein Gruppenname ein technischer AD-Gruppenname ist.
    Technische Namen enthalten typischerweise Punkte und/oder Unterstriche.
    """
    if not group_name:
        return False
    
    has_dot = '.' in group_name
    #has_underscore = '_' in group_name
    has_space = ' ' in group_name
    #starts_with_prefix = any(group_name.lower().startswith(prefix) for prefix in ['ef.', 'ph.', 'bs.', 'md.'])
    
    #return (has_dot and has_underscore) or starts_with_prefix
    return (has_dot and not has_space)  # Technische Namen haben Punkte und keine Leerzeichen



def load_group_id_mapping(csv_path='conf/group_id_mapping.csv', logger=None):
    """
    Lädt Mapping von CN/DisplayName zu Group IDs.
    
    Returns:
        Tuple: (cn_map, displayname_map, max_no)
        - cn_map: {cn: (displayName, id), ...}
        - displayname_map: {displayName: [(cn, id), ...], ...}
        - max_no: höchste verwendete Nummer
    """
    cn_map = {}
    displayname_map = {}
    max_no = 0
    
    csv_path = Path(csv_path)
    if not csv_path.exists():
        if logger:
            logger.warning(f"Mapping file not found: {csv_path}")
        return cn_map, displayname_map, max_no
    
    try:
        with open(csv_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                no = row.get('no', '').strip()
                displayName = row.get('displayName', '').strip()
                cn = row.get('onPremisesSamAccountName', '').strip()
                group_id = row.get('id', '').strip()
                
                # Track max number
                if no:
                    try:
                        max_no = max(max_no, int(no))
                    except ValueError:
                        pass
                
                # Map CN to (displayName, id)
                if cn and group_id:
                    cn_map[cn] = (displayName, group_id)
                
                # Map displayName to list of (cn, id)
                if displayName and group_id:
                    if displayName not in displayname_map:
                        displayname_map[displayName] = []
                    displayname_map[displayName].append((cn, group_id))
        
        if logger:
            logger.info(f"Loaded {len(cn_map)} CN mappings and {len(displayname_map)} displayName mappings")
    
    except Exception as e:
        if logger:
            logger.error(f"Error loading mapping file: {e}")
    
    return cn_map, displayname_map, max_no


def append_to_mapping_file(csv_path, entries, logger=None):
    """
    Fügt neue Einträge zur Mapping-Datei hinzu.
    
    Args:
        csv_path: Pfad zur Mapping-Datei
        entries: Liste von (no, displayName, cn, id) Tupeln
    """
    csv_path = Path(csv_path)
    
    try:
        with open(csv_path, 'a', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            for entry in entries:
                writer.writerow(entry)
        
        if logger:
            logger.info(f"Appended {len(entries)} entries to mapping file")
    
    except Exception as e:
        if logger:
            logger.error(f"Error appending to mapping file: {e}")


def sanitize_cn_for_mailnickname(cn):
    """
    Konvertiert CN zu mailNickname Format (ersetzt Sonderzeichen).
    
    Microsoft Graph API ersetzt bestimmte Zeichen in mailNickname:
    - Parentheses () → underscore _
    - Andere Sonderzeichen werden ebenfalls ersetzt
    
    Args:
        cn: Original CN string (z.B. ef.u.iqms_qms_rqu_(responsible_quality_unit)_vapi_in01)
    
    Returns:
        Sanitized string für mailNickname Filter
    """
    # Replace known special characters that Microsoft converts to underscore
    sanitized = cn
    
    # Parentheses to underscore
    sanitized = sanitized.replace('(', '_')
    sanitized = sanitized.replace(')', '_')
    
    # Other special characters that might be replaced
    sanitized = sanitized.replace(' ', '_')
    sanitized = sanitized.replace('&', '_')
    sanitized = sanitized.replace("'", '_')
    sanitized = sanitized.replace(',', '_')
    logger.info(f"Sanitized CN for mailNickname: '{cn}' -> '{sanitized}'")
    return sanitized


def search_group_by_cn(cn, bearer_token, session=None, logger=None):
    """
    Sucht Gruppe nach mailNickname (v1.0) oder onPremisesSamAccountName (beta).
    
    Strategy:
    1. Try mailNickname with v1.0 API (sanitized CN)
    2. Fallback: Try onPremisesSamAccountName with beta API (original CN)
    
    Returns:
        List of (displayName, cn, id) oder []
    """
    if session is None:
        session = requests
    
    headers = {
        'Authorization': f'Bearer {bearer_token}',
        'Content-Type': 'application/json'
    }
    
    # Strategy 1: Try mailNickname with v1.0 (sanitized CN)
    sanitized_cn = sanitize_cn_for_mailnickname(cn)
    cn_escaped = sanitized_cn.replace("'", "''")
    
    endpoint_v1 = "https://graph.microsoft.com/v1.0/groups"
    params_v1 = {
        '$filter': f"mailNickname eq '{cn_escaped}'",
        '$select': 'displayName,mailNickname,onPremisesSamAccountName,id'
    }
    
    try:
        if logger:
            logger.debug(f"Searching by mailNickname (v1.0): '{sanitized_cn}' (original: '{cn}')")
        
        response = session.get(endpoint_v1, headers=headers, params=params_v1, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        results = []
        
        if data.get('value') and len(data['value']) > 0:
            for group in data['value']:
                displayName = group.get('displayName', '')
                # Prefer onPremisesSamAccountName (preserves special chars)
                group_cn = group.get('onPremisesSamAccountName') or group.get('mailNickname', '')
                group_id = group.get('id', '')
                if group_id:
                    results.append((displayName, group_cn, group_id))
                    if logger:
                        logger.info(f"✓ Found via mailNickname (v1.0): {displayName} (ID: {group_id})")
            
            return results
    
    except requests.exceptions.RequestException as e:
        if logger:
            logger.debug(f"mailNickname search (v1.0) failed for '{sanitized_cn}': {e}")
    
    # Strategy 2: Try Beta API with onPremisesSamAccountName
    cn_escaped_original = cn.replace("'", "''")
    endpoint_beta = "https://graph.microsoft.com/beta/groups"
    params_beta = {
        '$filter': f"onPremisesSamAccountName eq '{cn_escaped_original}'",
        '$select': 'displayName,mailNickname,onPremisesSamAccountName,id'
    }
    
    try:
        if logger:
            logger.debug(f"Searching by onPremisesSamAccountName (beta): '{cn}'")
        
        response = session.get(endpoint_beta, headers=headers, params=params_beta, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        results = []
        
        if data.get('value'):
            for group in data['value']:
                displayName = group.get('displayName', '')
                group_cn = group.get('onPremisesSamAccountName') or group.get('mailNickname', '')
                group_id = group.get('id', '')
                if group_id:
                    results.append((displayName, group_cn, group_id))
                    if logger:
                        logger.info(f"✓ Found via onPremisesSamAccountName (beta): {displayName} (ID: {group_id})")
        
        return results
        
    except requests.exceptions.RequestException as e:
        if logger:
            error_detail = ""
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_json = e.response.json()
                    if 'error' in error_json:
                        error_detail = f" - {error_json['error'].get('message', '')}"
                except:
                    pass
            logger.error(f"Error searching group by CN '{cn}' (both strategies failed): {e}{error_detail}")
        return []


def search_group_by_displayname(displayName, bearer_token, session=None, logger=None, obs_logger=None):
    """
    Sucht Gruppe nach displayName.
    
    Returns:
        List of (displayName, cn, id) oder []
    """
    # Escape single quotes for OData (replace ' with '')
    displayName_escaped = displayName.replace("'", "''")
    
    endpoint = "https://graph.microsoft.com/v1.0/groups"
    params = {
        '$filter': f"displayName eq '{displayName_escaped}'",
        '$select': 'displayName,onPremisesSamAccountName,id'
    }
    
    headers = {
        'Authorization': f'Bearer {bearer_token}',
        'Content-Type': 'application/json'
    }
    
    # Use provided session or create default
    if session is None:
        session = requests
    
    try:
        response = session.get(endpoint, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        results = []
        
        if data.get('value'):
            for group in data['value']:
                dn = group.get('displayName', '')
                group_cn = group.get('onPremisesSamAccountName', '')
                group_id = group.get('id', '')
                if group_id:
                    results.append((dn, group_cn, group_id))
            
            # Observation: Mehrere Gruppen gefunden
            if len(results) > 1 and obs_logger:
                obs_logger.info(f"{'Multiple groups found for displayName':<60} | {displayName} (Found: {len(results)})")
        
        return results
    
    except requests.exceptions.RequestException as e:
        if logger:
            logger.error(f"Error searching group by displayName '{displayName}': {e}")
        return []


def resolve_group_id(group_cn, cn_map, displayname_map, bearer_token, next_no, mapping_updates, session=None, logger=None, obs_logger=None):
    """
    Löst Group ID auf - über Cache oder API.
    
    Returns:
        Tuple: (group_id or None, updated_next_no)
    """
    # 1. Prüfe CN in Cache
    if group_cn in cn_map:
        displayName, group_id = cn_map[group_cn]
        return group_id, next_no
    
    # 2. Suche via API nach CN
    results = search_group_by_cn(group_cn, bearer_token, session, logger)
    
    if results:
        # Gefunden via CN
        for displayName, found_cn, group_id in results:
            # Update Cache
            cn_map[group_cn] = (displayName, group_id)
            
            # Mark for file update
            mapping_updates.append((next_no, displayName, group_cn, group_id))
            next_no += 1
        
        # Return first result's ID
        return results[0][2], next_no
    
    # 3. Fallback: Suche nach displayName (extrahiere aus CN oder verwende leer)
    # Da wir keinen displayName haben, können wir hier nicht weitersuchen
    # Dies sollte idealerweise aus dem Input CSV kommen
    if logger:
        logger.warning(f"Group not found by CN: {group_cn}")
    
    return None, next_no


def get_group_members_batch(group_ids_dict, bearer_token, session=None, logger=None, obs_logger=None):
    """
    Ruft Gruppenmitglieder über Graph API Batch Endpoint ab.
    
    Args:
        group_ids_dict: {group_cn: group_id, ...}
        bearer_token: Bearer Token
        session: requests Session (optional)
    
    Returns:
        {group_cn: [members], ...}
    """
    results = {}
    
    # Use provided session or create default
    if session is None:
        session = requests
    
    # Erstelle Batch-Requests (max 20 pro Batch)
    group_items = list(group_ids_dict.items())
    batch_size = 20
    
    for batch_start in range(0, len(group_items), batch_size):
        batch_items = group_items[batch_start:batch_start + batch_size]
        
        # Erstelle Batch Request
        batch_requests = []
        for idx, (group_cn, group_id) in enumerate(batch_items):
            if not group_id:
                results[group_cn] = []
                continue
            
            # Log the first few requests for debugging
            if idx < 3 and logger:
                logger.info(f"Adding batch request: CN={group_cn}, ID={group_id}")
            
            batch_requests.append({
                "id": str(idx),
                "method": "GET",
                "url": f"/groups/{group_id}/members?$select=userPrincipalName,onPremisesSamAccountName,accountEnabled,mail"
            })
        
        if not batch_requests:
            continue
        
        # Sende Batch Request
        batch_endpoint = "https://graph.microsoft.com/v1.0/$batch"
        headers = {
            'Authorization': f'Bearer {bearer_token}',
            'Content-Type': 'application/json'
        }
        
        batch_body = {
            "requests": batch_requests
        }
        
        try:
            response = session.post(batch_endpoint, headers=headers, json=batch_body, timeout=60)
            response.raise_for_status()
            
            batch_response = response.json()
            
            # Log first batch for debugging
            if batch_start == 0 and logger:
                logger.info(f"Batch response received, processing {len(batch_response.get('responses', []))} responses")
            
            # Parse Batch Response
            for resp in batch_response.get('responses', []):
                request_id = int(resp.get('id', -1))
                if request_id < 0 or request_id >= len(batch_items):
                    continue
                
                group_cn, group_id = batch_items[request_id]
                status = resp.get('status', 0)
                
                if status == 200:
                    body = resp.get('body', {})
                    members_data = body.get('value', [])
                    
                    members = []
                    for member in members_data:
                        upn = member.get('userPrincipalName', '')
                        alias = member.get('onPremisesSamAccountName', '')
                        account_enabled = member.get('accountEnabled', None)
                        
                        # Observation: Kein Alias gefunden
                        if upn and not alias and obs_logger:
                            obs_logger.info(f"{'No Alias found for user':<60} | {upn}")
                        
                        # Map User Status
                        if account_enabled is True:
                            user_status = "Enabled"
                        elif account_enabled is False:
                            user_status = "Disabled"
                        else:
                            user_status = "Unknown"
                        
                        members.append({
                            'User': upn,
                            'Alias': alias,
                            'User Status': user_status
                        })
                    
                    results[group_cn] = members
                else:
                    # Fehler bei diesem Request - log details
                    error_msg = f"Batch request failed for group {group_cn}: Status {status}"
                    if 'body' in resp:
                        error_body = resp.get('body', {})
                        if 'error' in error_body:
                            error_detail = error_body['error'].get('message', '')
                            error_msg += f" - {error_detail}"
                    if logger:
                        logger.warning(error_msg)
                    results[group_cn] = []
        
        except requests.exceptions.RequestException as e:
            if logger:
                logger.error(f"Error in batch request: {e}")
            # Mark all groups in this batch as failed
            for group_cn, group_id in batch_items:
                if group_cn not in results:
                    results[group_cn] = []
    
    return results


def process_csv(input_file, output_file, silent=False, logger=None, obs_logger=None):
    """
    Liest CSV mit AD Security Groups, fragt Mitglieder ab und erweitert CSV.
    
    Args:
        input_file: Pfad zum Input-CSV (persona, AD Security Group, DocUnit)
        output_file: Pfad zum Output-CSV (erweitert mit User, Alias, User Status)
        silent: Wenn True, wird weniger Output erzeugt (für Batch-Verarbeitung)
        logger: Logger-Instanz für Fehlerprotokollierung
        obs_logger: Observations Logger
        
    Returns:
        Dictionary mit Statistiken
    """
    if not silent:
        print(f"\n{'='*80}")
        print(f"CSV Enrichment mit AD User-Daten (MICROSOFT GRAPH API)")
        print(f"{'='*80}\n")
        print(f"Input:  {input_file}")
        print(f"Output: {output_file}\n")
    
    # Bearer Token laden
    bearer_token = os.getenv('BEARER_TOKEN')
    if not bearer_token:
        error_msg = "BEARER_TOKEN environment variable is not set"
        if logger:
            logger.error(error_msg)
        print(f"✗ {error_msg}")
        raise ValueError(error_msg)
    
    # Create requests session with proxy support
    session = get_requests_session()
    
    # Token Validität prüfen
    if not silent:
        log_token_validity(bearer_token, logger)
    
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
        print(f"  - Übersprungene 'displayName' Namen: {len(skipped_groups)}")
        if skipped_groups:
            print(f"\n⚠ Übersprungene Gruppen (erste 10):")
            for group in skipped_groups[:10]:
                print(f"    - {group}")
            if len(skipped_groups) > 10:
                print(f"    ... und {len(skipped_groups) - 10} weitere")
        print()
    
    # Mapping laden
    if not silent:
        print(f"{'='*80}")
        print(f"Lade Group ID Mapping...")
        print(f"{'='*80}\n")
    
    cn_map, displayname_map, max_no = load_group_id_mapping(logger=logger)
    next_no = max_no + 1
    mapping_updates = []
    
    # Group IDs auflösen
    if not silent:
        print(f"{'='*80}")
        print(f"Löse Group IDs für {len(technical_groups)} Gruppen auf...")
        print(f"{'='*80}\n")
    
    group_ids_dict = {}
    groups_not_found = []
    
    batch_start = datetime.now()
    
    for group_cn in technical_groups:
        group_id, next_no = resolve_group_id(
            group_cn, cn_map, displayname_map, bearer_token, 
            next_no, mapping_updates, session, logger, obs_logger
        )
        
        if group_id:
            group_ids_dict[group_cn] = group_id
        else:
            groups_not_found.append(group_cn)
            group_ids_dict[group_cn] = None
    
    # Mapping-Updates speichern
    if mapping_updates:
        if not silent:
            print(f"✓ {len(mapping_updates)} neue Gruppen entdeckt - aktualisiere Mapping-Datei...")
        append_to_mapping_file('conf/group_id_mapping.csv', mapping_updates, logger)
    
    # Mitglieder abrufen
    if not silent:
        print(f"\n{'='*80}")
        print(f"⚡ Rufe Mitglieder für {len(group_ids_dict)} Gruppen ab (Graph API Batch)...")
        print(f"{'='*80}\n")
    
    group_members_cache = get_group_members_batch(group_ids_dict, bearer_token, session, logger, obs_logger)
    
    batch_end = datetime.now()
    batch_duration = (batch_end - batch_start).total_seconds()
    
    if not silent:
        print(f"\n⏱ API-Abfrage dauerte: {batch_duration:.1f} Sekunden")
    
    # Statistiken sammeln
    groups_found = {}
    timeout_groups = []
    
    for group_name, members in group_members_cache.items():
        if members is None:
            timeout_groups.append(group_name)
            group_members_cache[group_name] = []
        elif members:
            groups_found[group_name] = len(members)
    
    if not silent:
        print(f"\n✓ API-Abfrage abgeschlossen")
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
    
    report = f"""# CSV Enrichment Report (Microsoft Graph API)

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
        report += "*HINWEIS: Timeout bedeutet, dass die API-Anfrage abgebrochen wurde.*\n\n"
        for group in unique_timeout:
            report += f"- ⏱ {group}\n"
    
    report += "\n---\n*Generiert automatisch durch enrich_csv_with_users_msgraph.py*\n"
    
    return report


def batch_process(input_dir, output_dir, report_file):
    """
    Verarbeitet alle CSV-Dateien aus einem Verzeichnis im Batch-Modus.
    """
    logger = setup_logging()
    obs_logger, obs_file = setup_observations_log()
    
    # Gesamtzeit messen
    total_start = datetime.now()
    
    logger.info("="*80)
    logger.info("BATCH ENRICHMENT (MICROSOFT GRAPH API)")
    logger.info("="*80)
    
    print(f"\n{'='*80}")
    print(f"BATCH ENRICHMENT (MICROSOFT GRAPH API)")
    print(f"⚡ Verwendet Azure AD / Entra ID statt on-premises PowerShell")
    print(f"{'='*80}\n")
    print(f"Input-Verzeichnis:  {input_dir}")
    print(f"Output-Verzeichnis: {output_dir}")
    print(f"Report-Datei:       {report_file}")
    print(f"Observations-Log:   {obs_file}\n")
    
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
            stats = process_csv(str(csv_file), str(output_file), silent=False, logger=logger, obs_logger=obs_logger)
            
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
    print(f"✓ Observations Log: {obs_file}")
    
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
        description='Erweitert CSV mit AD Security Group Mitgliedern (MICROSOFT GRAPH API)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚡ MICROSOFT GRAPH API:
  Verwendet Azure AD / Entra ID statt on-premises PowerShell.
  Batch-Optimierung für beste Performance!

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
    parser.add_argument('--report', help='Report-Datei (Standard: exports/enrichment_report_msgraph.md)')
    
    args = parser.parse_args()
    
    if not args.input and not args.output and not args.batch:
        print("⚡ MICROSOFT GRAPH API - Batch-Verarbeitung\n")
        args.batch = True
    
    if args.batch:
        input_dir = Path(args.input_dir) if args.input_dir else project_root / "exports" / "splitted"
        output_dir = Path(args.output_dir) if args.output_dir else project_root / "exports" / "enriched"
        report_file = Path(args.report) if args.report else project_root / "exports" / "enrichment_report_msgraph.md"
        
        batch_process(input_dir, output_dir, report_file)
        return
    
    if not args.input or not args.output:
        print("✗ Fehler: --input und --output erforderlich!")
        print('-i', '--input', help='Input CSV-Datei')
        print('-o', '--output', help='Output CSV-Datei')
        print('--batch', action='store_true', help='Batch-Modus')
        print('--input-dir', help='Input-Verzeichnis (Standard: exports/splitted)')
        print('--output-dir', help='Output-Verzeichnis (Standard: exports/enriched)')
        print('--report', help='Report-Datei (Standard: exports/enrichment_report_msgraph.md)')
        sys.exit(1)
    
    logger = setup_logging()
    obs_logger, obs_file = setup_observations_log()
    
    process_csv(args.input, args.output, logger=logger, obs_logger=obs_logger)
    print(f"✓ Fertig! Erweiterte CSV: {args.output}")
    print(f"✓ Observations Log: {obs_file}\n")


if __name__ == "__main__":
    main()
