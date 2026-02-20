"""
CSV enrichment with AD user data (Microsoft Graph API).
Reads AD security groups from CSV, retrieves members, and enriches rows with user data.
Supports batch processing of multiple files from a directory.

MICROSOFT GRAPH API: Uses Azure AD / Entra ID instead of on-premises PowerShell.
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
from datetime import datetime, timezone, timedelta
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

ERROR_GROUP_TEXT = "ERROR: Could not find group"
NEAR_EXPIRY_THRESHOLD_SECONDS = 10 * 60
_near_expiry_user_decision = None


def log_rest_call(logger, method, endpoint, params=None):
    """Logs the REST call including query parameters."""
    if not logger:
        return

    try:
        prepared = requests.Request(method, endpoint, params=params).prepare()
        logger.info(f"MS Graph REST call -> {method.upper()} {prepared.url}")
    except Exception:
        logger.info(f"MS Graph REST call -> {method.upper()} {endpoint}")


def mapping_entry_exists(cn_map, displayname_map, display_name, cn, group_id):
    """Checks whether a mapping entry already exists (duplicate protection)."""
    if cn and cn in cn_map and cn_map[cn][1] == group_id:
        return True

    if display_name and display_name in displayname_map:
        for existing_cn, existing_id in displayname_map[display_name]:
            if existing_id == group_id and (not cn or existing_cn == cn):
                return True

    return False


def get_requests_session():
    """
    Creates a requests session with proxy support.
    Uses system proxy settings or NO_PROXY from .env.
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


def get_user_input(prompt, default_value):
    """Prompts the user for input with a suggested default value."""
    print(f"\n{prompt}")
    print(f"Suggested: {default_value}")
    user_input = input("Enter full path (or press Enter to use suggested): ").strip()

    if user_input:
        return user_input
    return str(default_value)


def prompt_for_single_file_paths(project_root, current_input=None, current_output=None):
    """Prompts for input/output paths in single-file mode with safe defaults."""
    default_input = Path(current_input) if current_input else project_root / "exports" / "persona_sg_mapping.csv"
    input_path = Path(get_user_input("[1/2] Input CSV file:", default_input))

    derived_default_output = (
        Path(current_output)
        if current_output
        else input_path.parent / f"{input_path.stem}_enriched{input_path.suffix or '.csv'}"
    )

    while True:
        output_path = Path(get_user_input("[2/2] Output CSV file:", derived_default_output))

        if output_path.parent != input_path.parent:
            print("✗ Output file must be in the same folder as input file.")
            print(f"  Input folder:  {input_path.parent}")
            print(f"  Output folder: {output_path.parent}")
            continue

        if output_path.name == input_path.name:
            print("✗ Output filename must be different from input filename.")
            print(f"  Input file:  {input_path.name}")
            print(f"  Output file: {output_path.name}")
            continue

        return input_path, output_path


def setup_logging():
    """
    Configures logging with file and console handlers.
    """
    project_root = Path(__file__).parent
    log_dir = project_root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"get_users_and_groups_from_ad_{timestamp}.log"
    
    # Configure logger
    logger = logging.getLogger('enrichment')
    logger.setLevel(logging.DEBUG)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # File handler - detailed logs
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    
    # Console handler - info, warnings, and errors
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"Logging initialized. Log file: {log_file}")
    return logger


def setup_observations_log():
    """
    Configures observations log for warnings and notable events.
    """
    project_root = Path(__file__).parent
    reports_dir = project_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    obs_file = reports_dir / f"observations_from_get_users_and_groups_{timestamp}.md"
    
    # Observations Logger
    obs_logger = logging.getLogger('observations')
    obs_logger.setLevel(logging.INFO)
    obs_logger.propagate = False  # Do not propagate to parent logger
    
    # Prevent duplicate handlers
    if obs_logger.handlers:
        return obs_logger, obs_file
    
    # File Handler
    obs_handler = logging.FileHandler(obs_file, encoding='utf-8', mode='w')
    obs_handler.setLevel(logging.INFO)
    obs_formatter = logging.Formatter('%(message)s')
    obs_handler.setFormatter(obs_formatter)
    
    obs_logger.addHandler(obs_handler)
    
    # Write header
    obs_logger.info("="*100)
    obs_logger.info(f"OBSERVATIONS LOG - get_users_and_groups_from_ad.py")
    obs_logger.info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    obs_logger.info("="*100)
    obs_logger.info(f"{'Observation Description':<60} | {'userPrincipalName/Details'}")
    obs_logger.info("-"*100)
    
    return obs_logger, obs_file


def format_duration(delta) -> str:
    """Formats timedelta as a readable string."""
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


def get_token_expiration_utc(token: str) -> Optional[datetime]:
    """Extracts token expiration timestamp (UTC) from a JWT bearer token."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None

        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_bytes.decode("utf-8"))

        exp = payload.get("exp")
        if not exp:
            return None

        return datetime.fromtimestamp(int(exp), tz=timezone.utc)
    except Exception:
        return None


def print_expired_token_error(exp_time: datetime, explorer_url: str) -> None:
    """Prints a highlighted console message for expired bearer token errors."""
    no_color = os.getenv("NO_COLOR", "").lower() in ("1", "true", "yes")
    use_color = sys.stdout.isatty() and not no_color

    if use_color:
        red = "\033[91m"
        yellow = "\033[93m"
        cyan = "\033[96m"
        bold = "\033[1m"
        reset = "\033[0m"
    else:
        red = yellow = cyan = bold = reset = ""

    border = f"{red}{bold}{'=' * 90}{reset}"
    print(border)
    print(f"{red}{bold}✗ BEARER TOKEN EXPIRED{reset}")
    print(f"{yellow}Token expired at: {exp_time.isoformat()}{reset}")
    print(f"Please refresh BEARER_TOKEN in .env and run again.")
    print(f"{cyan}Link: {explorer_url}{reset}")
    print(border)


def print_near_expiry_warning(exp_time: datetime, remaining: timedelta, explorer_url: str) -> None:
    """Prints a highlighted console message for near-expiry bearer token warnings."""
    no_color = os.getenv("NO_COLOR", "").lower() in ("1", "true", "yes")
    use_color = sys.stdout.isatty() and not no_color

    if use_color:
        yellow = "\033[93m"
        cyan = "\033[96m"
        bold = "\033[1m"
        reset = "\033[0m"
    else:
        yellow = cyan = bold = reset = ""

    border = f"{yellow}{bold}{'=' * 90}{reset}"
    print(border)
    print(f"{yellow}{bold}⚠ BEARER TOKEN EXPIRING SOON{reset}")
    print(f"{yellow}Expires at: {exp_time.isoformat()}{reset}")
    print(f"{yellow}Remaining: {format_duration(remaining)}{reset}")
    print("The token expires within the next 10 minutes.")
    print(f"{cyan}Refresh here if needed: {explorer_url}{reset}")
    print(border)


def enforce_bearer_token_policy(token: str, logger=None, prompt_user: bool = True) -> None:
    """Enforces token policy: stop if expired, confirm if expiring within 10 minutes."""
    global _near_expiry_user_decision

    exp_time = get_token_expiration_utc(token)
    if not exp_time:
        message = "Bearer token validity cannot be determined from JWT claims; continuing without expiry enforcement"
        if logger:
            logger.warning(message)
        print(f"⚠ {message}")
        return

    now = datetime.now(timezone.utc)
    remaining = exp_time - now
    remaining_seconds = int(remaining.total_seconds())

    if remaining_seconds <= 0:
        explorer_url = "https://developer.microsoft.com/en-us/graph/graph-explorer"
        message = (
            f"Bearer token has expired at {exp_time.isoformat()}. "
            "Please refresh BEARER_TOKEN in .env and run again. "
            f"Link: [{explorer_url}]({explorer_url})"
        )
        if logger:
            logger.error(message)
        print_expired_token_error(exp_time, explorer_url)
        raise ValueError(message)

    if remaining_seconds <= NEAR_EXPIRY_THRESHOLD_SECONDS:
        explorer_url = "https://developer.microsoft.com/en-us/graph/graph-explorer"
        warning = (
            f"Bearer token will expire soon at {exp_time.isoformat()} "
            f"(remaining {format_duration(remaining)})."
        )
        if logger:
            logger.warning(warning)
        print_near_expiry_warning(exp_time, remaining, explorer_url)

        if _near_expiry_user_decision is None:
            if prompt_user:
                try:
                    answer = input("Do you want to continue processing? [y/N]: ").strip().lower()
                except Exception:
                    answer = ""
                _near_expiry_user_decision = answer in ("y", "yes")
            else:
                _near_expiry_user_decision = False

        if not _near_expiry_user_decision:
            message = "Processing cancelled because the bearer token expires within the next 10 minutes."
            if logger:
                logger.warning(message)
            print(f"✗ {message}")
            raise ValueError(message)


def log_token_validity(token: str, logger=None) -> None:
    """Checks and logs JWT token validity."""
    try:
        exp_time = get_token_expiration_utc(token)
        if not exp_time:
            if logger:
                logger.warning("Bearer token does not look like a JWT; validity cannot be determined")
            return

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
    Checks whether a group name is a technical AD group name.
    Technical names usually contain dots and/or underscores.
    """
    if not group_name:
        return False
    
    has_dot = '.' in group_name
    #has_underscore = '_' in group_name
    has_space = ' ' in group_name
    #starts_with_prefix = any(group_name.lower().startswith(prefix) for prefix in ['ef.', 'ph.', 'bs.', 'md.'])
    
    #return (has_dot and has_underscore) or starts_with_prefix
    return (has_dot and not has_space)  # Technical names contain dots and no spaces



def load_group_id_mapping(csv_path='conf/group_id_mapping.csv', logger=None):
    """
    Loads mapping from CN/displayName to group IDs.
    
    Returns:
        Tuple: (cn_map, displayname_map, max_no, error_entries)
        - cn_map: {cn: (displayName, id), ...}
        - displayname_map: {displayName: [(cn, id), ...], ...}
        - max_no: highest used number
        - error_entries: set of already existing error rows
    """
    cn_map = {}
    displayname_map = {}
    error_entries = set()
    max_no = 0
    
    csv_path = Path(csv_path)
    if not csv_path.exists():
        if logger:
            logger.warning(f"Mapping file not found: {csv_path}")
        return cn_map, displayname_map, max_no, error_entries
    
    try:
        with open(csv_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                no = row.get('no', '').strip()
                displayName = row.get('displayName', '').strip()
                cn = row.get('onPremisesSamAccountName', '').strip()
                mail_nickname = row.get('mailNickname', '').strip()
                group_id = row.get('id', '').strip()
                
                # Track max number
                if no:
                    try:
                        max_no = max(max_no, int(no))
                    except ValueError:
                        pass
                
                # Track existing error rows for deduplication, but do not use them as valid mappings
                if group_id.startswith(ERROR_GROUP_TEXT):
                    error_entries.add((displayName, cn, mail_nickname, group_id))
                    continue

                # Map CN to (displayName, id)
                if cn and group_id:
                    cn_map[cn] = (displayName, group_id)
                
                # Map displayName to list of (cn, id)
                if displayName and group_id:
                    if displayName not in displayname_map:
                        displayname_map[displayName] = []
                    displayname_map[displayName].append((cn, group_id))
        
        if logger:
            logger.info(
                f"Loaded {len(cn_map)} CN mappings and {len(displayname_map)} displayName mappings "
                f"({len(error_entries)} error rows ignored as lookup source)"
            )
    
    except Exception as e:
        if logger:
            logger.error(f"Error loading mapping file: {e}")
    
    return cn_map, displayname_map, max_no, error_entries


def append_to_mapping_file(csv_path, entries, logger=None):
    """
    Appends new entries to the mapping file.
    
    Args:
        csv_path: path to the mapping file
        entries: list of (no, displayName, cn, mailNickname, id) tuples
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


def sanitize_cn_for_mailnickname(cn, logger=None):
    """
    Converts CN to mailNickname format (replaces special characters).
    
    Microsoft Graph API replaces specific characters in mailNickname:
    - Parentheses () → underscore _
    - Other special characters are also replaced
    
    Args:
        cn: original CN string (e.g. ef.u.iqms_qms_rqu_(responsible_quality_unit)_vapi_in01)
    
    Returns:
        Sanitized string for mailNickname filter
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
    if logger:
        logger.info(f"Sanitized CN for mailNickname: '{cn}' -> '{sanitized}'")
    return sanitized


def search_group_by_cn(cn, bearer_token, session=None, logger=None):
    """
    Searches a group by mailNickname (v1.0) or onPremisesSamAccountName (beta).
    
    Strategy:
    1. Try mailNickname with v1.0 API (sanitized CN)
    2. Fallback: Try onPremisesSamAccountName with beta API (original CN)
    
    Returns:
        List of (displayName, cn, mailNickname, id) or []
    """
    if session is None:
        session = requests
    
    headers = {
        'Authorization': f'Bearer {bearer_token}',
        'Content-Type': 'application/json'
    }
    
    # Strategy 1: Try mailNickname with v1.0 (sanitized CN)
    sanitized_cn = sanitize_cn_for_mailnickname(cn, logger)
    cn_escaped = sanitized_cn.replace("'", "''")
    
    endpoint_v1 = "https://graph.microsoft.com/v1.0/groups"
    params_v1 = {
        '$filter': f"mailNickname eq '{cn_escaped}'",
        '$select': 'displayName,mailNickname,onPremisesSamAccountName,id'
    }
    
    try:
        if logger:
            logger.info(f"MS Graph group search -> attribute=mailNickname, value='{sanitized_cn}', endpoint=v1.0/groups")
            log_rest_call(logger, 'GET', endpoint_v1, params_v1)
            logger.debug(f"Searching by mailNickname (v1.0): '{sanitized_cn}' (original: '{cn}')")
        
        response = session.get(endpoint_v1, headers=headers, params=params_v1, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        results = []
        
        if data.get('value') and len(data['value']) > 0:
            for group in data['value']:
                displayName = group.get('displayName', '')
                # Prefer onPremisesSamAccountName (preserves special chars)
                group_cn = group.get('onPremisesSamAccountName') or cn
                mail_nickname = group.get('mailNickname', '')
                group_id = group.get('id', '')
                if group_id:
                    results.append((displayName, group_cn, mail_nickname, group_id))
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
            logger.info(f"MS Graph group search -> attribute=onPremisesSamAccountName, value='{cn}', endpoint=beta/groups")
            log_rest_call(logger, 'GET', endpoint_beta, params_beta)
            logger.debug(f"Searching by onPremisesSamAccountName (beta): '{cn}'")
        
        response = session.get(endpoint_beta, headers=headers, params=params_beta, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        results = []
        
        if data.get('value'):
            for group in data['value']:
                displayName = group.get('displayName', '')
                group_cn = group.get('onPremisesSamAccountName') or cn
                mail_nickname = group.get('mailNickname', '')
                group_id = group.get('id', '')
                if group_id:
                    results.append((displayName, group_cn, mail_nickname, group_id))
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
    Searches a group by displayName.
    
    Returns:
        List of (displayName, cn, mailNickname, id) or []
    """
    # Escape single quotes for OData (replace ' with '')
    displayName_escaped = displayName.replace("'", "''")
    
    endpoint = "https://graph.microsoft.com/v1.0/groups"
    params = {
        '$filter': f"displayName eq '{displayName_escaped}'",
        '$select': 'displayName,onPremisesSamAccountName,mailNickname,id'
    }
    
    headers = {
        'Authorization': f'Bearer {bearer_token}',
        'Content-Type': 'application/json'
    }
    
    # Use provided session or create default
    if session is None:
        session = requests
    
    try:
        if logger:
            logger.info(f"MS Graph group search -> attribute=displayName, value='{displayName}', endpoint=v1.0/groups")
            log_rest_call(logger, 'GET', endpoint, params)

        response = session.get(endpoint, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        results = []
        
        if data.get('value'):
            for group in data['value']:
                dn = group.get('displayName', '')
                group_cn = group.get('onPremisesSamAccountName', '')
                mail_nickname = group.get('mailNickname', '')
                group_id = group.get('id', '')
                if group_id:
                    results.append((dn, group_cn, mail_nickname, group_id))
            
            # Observation: Multiple groups found
            if len(results) > 1 and obs_logger:
                obs_logger.info(f"{'Multiple groups found for displayName':<60} | {displayName} (Found: {len(results)})")
        
        return results
    
    except requests.exceptions.RequestException as e:
        if logger:
            logger.error(f"Error searching group by displayName '{displayName}': {e}")
        return []


def resolve_group_id(group_cn, cn_map, displayname_map, bearer_token, next_no, mapping_updates, error_entries=None, session=None, logger=None, obs_logger=None):
    """
    Resolves group ID via cache or API.
    
    Returns:
        Tuple: (group_id or None, updated_next_no)
    """
    is_technical = is_technical_group_name(group_cn)

    # 1. Resolve technical names via CN cache first
    if is_technical and group_cn in cn_map:
        displayName, group_id = cn_map[group_cn]
        return group_id, next_no

    # 1b. Resolve non-technical names via displayName cache
    if (not is_technical) and group_cn in displayname_map and displayname_map[group_cn]:
        cached_cn, cached_group_id = displayname_map[group_cn][0]
        if logger:
            logger.info(f"Mapping cache hit (displayName): '{group_cn}' -> ID {cached_group_id}")
        return cached_group_id, next_no

    # 2. Search via API
    if is_technical:
        results = search_group_by_cn(group_cn, bearer_token, session, logger)
    else:
        if logger:
            logger.info(f"Non-technical group name detected -> searching by displayName: '{group_cn}'")
        results = search_group_by_displayname(group_cn, bearer_token, session, logger, obs_logger)
    
    if results:
        # Found via API
        for displayName, found_cn, mail_nickname, group_id in results:
            mapped_cn = found_cn or group_cn
            mapped_mail_nickname = mail_nickname or sanitize_cn_for_mailnickname(group_cn, logger)

            # Duplicate protection: append only new mapping entries
            if mapping_entry_exists(cn_map, displayname_map, displayName, mapped_cn, group_id):
                if logger:
                    logger.info(
                        f"Skip duplicate mapping entry: displayName='{displayName}', onPremisesSamAccountName='{mapped_cn}', id='{group_id}'"
                    )
                continue

            # Update Cache
            cn_map[mapped_cn] = (displayName, group_id)
            if displayName not in displayname_map:
                displayname_map[displayName] = []
            displayname_map[displayName].append((mapped_cn, group_id))
            
            # Mark for file update
            mapping_updates.append((next_no, displayName, mapped_cn, mapped_mail_nickname, group_id))
            next_no += 1
        
        # Return first result ID
        return results[0][3], next_no
    
    if error_entries is None:
        error_entries = set()

    if is_technical:
        # Searched by mailNickname (sanitized CN)
        search_value = sanitize_cn_for_mailnickname(group_cn, logger)
        error_row = (ERROR_GROUP_TEXT, ERROR_GROUP_TEXT, search_value, ERROR_GROUP_TEXT)
    else:
        # Searched by displayName (original value)
        error_row = (group_cn, ERROR_GROUP_TEXT, ERROR_GROUP_TEXT, ERROR_GROUP_TEXT)

    if error_row not in error_entries:
        mapping_updates.append((next_no, *error_row))
        error_entries.add(error_row)
        next_no += 1
    elif logger:
        logger.info(f"Skip duplicate error mapping entry for group: {group_cn}")

    if obs_logger:
        obs_logger.info(f"Group Not Found: {group_cn}")

    if logger:
        logger.warning(f"Group not found in MS Graph: {group_cn}")
    
    return None, next_no


def get_group_members_batch(group_ids_dict, bearer_token, session=None, logger=None, obs_logger=None):
    """
    Retrieves group members via Microsoft Graph batch endpoint.
    
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
    
    # Build batch requests (max 20 per batch)
    group_items = list(group_ids_dict.items())
    batch_size = 20
    
    for batch_start in range(0, len(group_items), batch_size):
        batch_items = group_items[batch_start:batch_start + batch_size]
        
        # Build batch request
        batch_requests = []
        for idx, (group_cn, group_id) in enumerate(batch_items):
            if not group_id:
                results[group_cn] = []
                continue
            
            if logger:
                logger.info(f"Adding batch request: CN={group_cn}, ID={group_id}")
                logger.info(
                    "MS Graph REST call -> GET "
                    f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"
                    "?$select=userPrincipalName,onPremisesSamAccountName,accountEnabled,mail"
                )
            
            batch_requests.append({
                "id": str(idx),
                "method": "GET",
                "url": f"/groups/{group_id}/members?$select=userPrincipalName,onPremisesSamAccountName,accountEnabled,mail"
            })
        
        if not batch_requests:
            continue
        
        # Send batch request
        batch_endpoint = "https://graph.microsoft.com/v1.0/$batch"
        headers = {
            'Authorization': f'Bearer {bearer_token}',
            'Content-Type': 'application/json'
        }
        
        batch_body = {
            "requests": batch_requests
        }
        
        try:
            if logger:
                log_rest_call(logger, 'POST', batch_endpoint)
                for req in batch_requests[:3]:
                    logger.info(f"MS Graph REST batch item -> {req.get('method', 'GET')} https://graph.microsoft.com/v1.0{req.get('url', '')}")

            response = session.post(batch_endpoint, headers=headers, json=batch_body, timeout=60)
            response.raise_for_status()
            
            batch_response = response.json()
            
            # Log first batch for debugging
            if batch_start == 0 and logger:
                logger.info(f"Batch response received, processing {len(batch_response.get('responses', []))} responses")
            
            # Parse batch response
            for resp in batch_response.get('responses', []):
                request_id = int(resp.get('id', -1))
                if request_id < 0 or request_id >= len(batch_items):
                    continue
                
                group_cn, group_id = batch_items[request_id]
                status = resp.get('status', 0)
                
                if status == 200:
                    body = resp.get('body', {})
                    members = []

                    page_no = 1
                    while True:
                        members_data = body.get('value', [])

                        for member in members_data:
                            upn = member.get('userPrincipalName', '')
                            alias = member.get('onPremisesSamAccountName', '')
                            account_enabled = member.get('accountEnabled', None)

                            # Observation: no alias found
                            if upn and not alias and obs_logger:
                                obs_logger.info(f"{'No Alias found for user':<60} | {upn}")

                            # Map user status
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

                        next_link = body.get('@odata.nextLink')
                        if not next_link:
                            break

                        page_no += 1
                        if logger:
                            logger.info(f"MS Graph REST call -> GET {next_link}")
                            logger.info(f"Pagination: fetching page {page_no} for group {group_cn} ({group_id})")

                        try:
                            next_response = session.get(next_link, headers=headers, timeout=60)
                            next_response.raise_for_status()
                            body = next_response.json()
                        except requests.exceptions.RequestException as e:
                            if logger:
                                logger.warning(
                                    f"Pagination request failed for group {group_cn} ({group_id}) on page {page_no}: {e}"
                                )
                            break

                    if len(members) == 0 and obs_logger:
                        obs_logger.info(f"Group with 0 members: {group_cn},{group_id}")
                    
                    results[group_cn] = members
                else:
                    # Request-level error - log details
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
    Reads CSV with AD security groups, retrieves members, and enriches CSV rows.
    
    Args:
        input_file: path to input CSV (persona, AD Security Group, DocUnit)
        output_file: path to output CSV (enriched with User, Alias, User Status)
        silent: when True, prints less output (for batch processing)
        logger: logger instance for error logging
        obs_logger: Observations Logger
        
    Returns:
        Dictionary with statistics
    """
    if not silent:
        print(f"\n{'='*80}")
        print(f"CSV enrichment with AD user data (MICROSOFT GRAPH API)")
        print(f"{'='*80}\n")
        print(f"Input:  {input_file}")
        print(f"Output: {output_file}\n")
    
    # Load bearer token
    bearer_token = os.getenv('BEARER_TOKEN')
    if not bearer_token:
        error_msg = "BEARER_TOKEN environment variable is not set"
        if logger:
            logger.error(error_msg)
        print(f"✗ {error_msg}")
        raise ValueError(error_msg)
    
    # Create requests session with proxy support
    session = get_requests_session()
    
    # Check token validity
    if not silent:
        enforce_bearer_token_policy(bearer_token, logger=logger, prompt_user=True)
        log_token_validity(bearer_token, logger)
    
    # Read CSV
    try:
        with open(input_file, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            input_rows = list(reader)
    except FileNotFoundError:
        if not silent:
            print(f"✗ Error: File '{input_file}' not found!")
        raise
    except Exception as e:
        if not silent:
            print(f"✗ Error while reading CSV: {e}")
        raise
    
    if not silent:
        print(f"✓ {len(input_rows)} rows loaded")
    
    # Collect unique AD security groups
    unique_groups = sorted(set(row['AD Security Group'] for row in input_rows))
    
    # Classify group types (for logging/reporting)
    technical_groups = []
    non_technical_groups = []
    
    for group in unique_groups:
        if is_technical_group_name(group):
            technical_groups.append(group)
        else:
            non_technical_groups.append(group)
    
    if not silent:
        print(f"✓ {len(unique_groups)} unique AD security groups found")
        print(f"  - Technical names: {len(technical_groups)}")
        print(f"  - Non-technical names (displayName): {len(non_technical_groups)}")
        if non_technical_groups:
            print(f"\nℹ Non-technical groups (first 10, searched via displayName):")
            for group in non_technical_groups[:10]:
                print(f"    - {group}")
            if len(non_technical_groups) > 10:
                print(f"    ... and {len(non_technical_groups) - 10} more")
        print()
    
    # Load mapping
    if not silent:
        print(f"{'='*80}")
        print(f"Loading group ID mapping...")
        print(f"{'='*80}\n")
    
    cn_map, displayname_map, max_no, error_entries = load_group_id_mapping(logger=logger)
    next_no = max_no + 1
    mapping_updates = []
    
    # Resolve group IDs
    if not silent:
        print(f"{'='*80}")
        print(f"Resolving group IDs for {len(unique_groups)} groups...")
        print(f"{'='*80}\n")
    
    group_ids_dict = {}
    groups_not_found = []
    
    batch_start = datetime.now()
    
    for group_cn in unique_groups:
        group_id, next_no = resolve_group_id(
            group_cn, cn_map, displayname_map, bearer_token, 
            next_no, mapping_updates, error_entries, session, logger, obs_logger
        )
        
        if group_id:
            group_ids_dict[group_cn] = group_id
        else:
            groups_not_found.append(group_cn)
            group_ids_dict[group_cn] = None
    
    # Persist mapping updates
    if mapping_updates:
        if not silent:
            print(f"✓ {len(mapping_updates)} new groups discovered - updating mapping file...")
        append_to_mapping_file('conf/group_id_mapping.csv', mapping_updates, logger)
    
    # Retrieve members
    if not silent:
        print(f"\n{'='*80}")
        print(f"⚡ Retrieving members for {len(group_ids_dict)} groups (Graph API batch)...")
        print(f"{'='*80}\n")
    
    group_members_cache = get_group_members_batch(group_ids_dict, bearer_token, session, logger, obs_logger)
    
    batch_end = datetime.now()
    batch_duration = (batch_end - batch_start).total_seconds()
    
    if not silent:
        print(f"\n⏱ API request duration: {batch_duration:.1f} seconds")
    
    # Collect statistics
    groups_found = {}
    timeout_groups = []
    
    for group_name, members in group_members_cache.items():
        if members is None:
            timeout_groups.append(group_name)
            group_members_cache[group_name] = []
        elif members:
            groups_found[group_name] = len(members)
    
    if not silent:
        print(f"\n✓ API request completed")
        print(f"  - Groups with members: {len(groups_found)}")
        print(f"  - Groups without members: {len(groups_not_found)}")
        print(f"  - Groups with timeout: {len(timeout_groups)}\n")
    
    if not silent:
        print(f"{'='*80}")
        print(f"Enriching CSV data...")
        print(f"{'='*80}\n")
    
    # Create new rows with user data
    output_rows = []
    total_users = 0
    groups_without_members = 0
    skipped_groups = []
    
    for row in input_rows:
        group_name = row['AD Security Group']
        
        members = group_members_cache.get(group_name, [])
        
        if members:
            # Create one new row per member
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
            # Group without members: add row without user data
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
    
    # Write enriched CSV
    try:
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
            fieldnames = ['persona', 'AD Security Group', 'DocUnit', 'User', 'Alias', 'User Status']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(output_rows)
        
        if not silent:
            print(f"✓ CSV successfully enriched and saved\n")
            print(f"{'='*80}")
            print(f"Statistics:")
            print(f"{'='*80}")
            print(f"  Input rows:                  {len(input_rows):6d}")
            print(f"  AD security groups:          {len(unique_groups):6d}")
            print(f"  Groups without members:      {groups_without_members:6d}")
            print(f"  Found users:                 {total_users:6d}")
            print(f"  Output rows:                 {len(output_rows):6d}")
            print(f"{'='*80}\n")
        
        # Return statistics
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
            print(f"✗ Error while writing CSV: {e}")
        raise


def generate_report(processed_files, skipped_files, failed_files, all_groups_found, all_groups_not_found, all_timeout_groups, all_skipped_groups, total_users):
    """
    Generates a markdown report for batch processing.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = f"""# CSV Enrichment Report (Microsoft Graph API)

**Timestamp:** {timestamp}

## Summary

- **Processed files:** {len(processed_files)}
- **Skipped files:** {len(skipped_files)}
- **Failed files:** {len(failed_files)}
- **Total users found:** {total_users}
- **AD groups without members:** {len(all_groups_not_found)}
- **AD groups with timeout:** {len(set(all_timeout_groups))}
- **Skipped "pretty" group names:** {len(set(all_skipped_groups))}

## Processed Files

"""
    
    if processed_files:
        for filename in processed_files:
            report += f"- ✓ {filename}\n"
    else:
        report += "*No files processed*\n"
    
    report += "\n## Skipped Files\n\n"
    
    if skipped_files:
        for filename in skipped_files:
            report += f"- ⊘ {filename} (already exists)\n"
    else:
        report += "*No files skipped*\n"
    
    report += "\n## Failed Files\n\n"
    
    if failed_files:
        for filename, error in failed_files:
            report += f"- ✗ {filename}\n"
            report += f"  - Error: `{error}`\n"
    else:
        report += "*No errors*\n"
    
    if all_skipped_groups:
        unique_skipped = sorted(set(all_skipped_groups))
        report += f"\n## Skipped 'pretty' group names ({len(unique_skipped)})\n\n"
        for group in unique_skipped[:20]:
            report += f"- ⚠ {group}\n"
        if len(unique_skipped) > 20:
            report += f"\n*... and {len(unique_skipped) - 20} more*\n"
    
    report += "\n## AD Group Statistics\n\n"
    
    if all_groups_found:
        report += f"### Groups with members ({len(all_groups_found)})\n\n"
        report += "| AD Security Group | User Count |\n"
        report += "|-------------------|-------------|\n"
        for group, count in sorted(all_groups_found.items(), key=lambda x: x[1], reverse=True):
            report += f"| {group} | {count} |\n"
    
    if all_groups_not_found:
        unique_not_found = sorted(set(all_groups_not_found))
        report += f"\n### Groups without members / not found ({len(unique_not_found)})\n\n"
        for group in unique_not_found:
            report += f"- ⚠ {group}\n"
    
    if all_timeout_groups:
        unique_timeout = sorted(set(all_timeout_groups))
        report += f"\n### Groups with timeout ({len(unique_timeout)})\n\n"
        report += "*NOTE: Timeout means the API request was aborted.*\n\n"
        for group in unique_timeout:
            report += f"- ⏱ {group}\n"
    
    report += "\n---\n*Generated automatically by get_users_and_groups_from_ad.py*\n"
    
    return report


def batch_process(input_dir, output_dir, report_file):
    """
    Processes all CSV files from a directory in batch mode.
    """
    logger = setup_logging()
    obs_logger, obs_file = setup_observations_log()
    
    # Measure total runtime
    total_start = datetime.now()
    
    logger.info("="*80)
    logger.info("BATCH ENRICHMENT (MICROSOFT GRAPH API)")
    logger.info("="*80)
    
    print(f"\n{'='*80}")
    print(f"BATCH ENRICHMENT (MICROSOFT GRAPH API)")
    print(f"⚡ Uses Azure AD / Entra ID instead of on-premises PowerShell")
    print(f"{'='*80}\n")
    print(f"Input directory:  {input_dir}")
    print(f"Output directory: {output_dir}")
    print(f"Report file:      {report_file}")
    print(f"Observations-Log:   {obs_file}\n")
    
    if not input_dir.exists():
        print(f"✗ Error: Input directory '{input_dir}' not found!")
        sys.exit(1)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    csv_files = sorted(input_dir.glob("*.csv"))
    
    if not csv_files:
        print(f"✗ No CSV files found in '{input_dir}'!")
        sys.exit(1)
    
    print(f"✓ {len(csv_files)} CSV file(s) found\n")
    
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
            print(f"[{idx:4d}/{len(csv_files)}] ⊘ Skipping: {csv_file.name} (already exists)")
            skipped_files.append(csv_file.name)
            continue
        
        print(f"\n{'='*80}")
        print(f"[{idx:4d}/{len(csv_files)}] Processing: {csv_file.name}")
        print(f"{'='*80}")
        
        logger.info(f"Processing file {idx}/{len(csv_files)}: {csv_file.name}")
        
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
            
            print(f"\n✓ Successfully processed: {csv_file.name}")
            print(f"  ⏱ Processing time: {file_duration:.1f} seconds")
            logger.info(f"Successfully processed: {csv_file.name} ({stats['total_users']} users, {file_duration:.1f}s)")
            
        except Exception as e:
            error_msg = f"Error while processing {csv_file.name}: {e}"
            print(f"\n✗ {error_msg}")
            logger.error(error_msg)
            failed_files.append((csv_file.name, str(e)))
    
    print(f"\n{'='*80}")
    print(f"GENERATING REPORT")
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
    print(f"\n✓ Report saved: {report_file}")
    print(f"✓ Observations Log: {obs_file}")
    
    # Calculate total runtime
    total_end = datetime.now()
    total_duration = (total_end - total_start).total_seconds()
    total_minutes = int(total_duration // 60)
    total_seconds = int(total_duration % 60)
    
    print(f"\n{'='*80}")
    print(f"BATCH ENRICHMENT COMPLETED")
    print(f"{'='*80}")
    print(f"  Processed:      {len(processed_files):4d}")
    print(f"  Skipped:        {len(skipped_files):4d}")
    print(f"  Failed:         {len(failed_files):4d}")
    print(f"  Total users:    {total_users:4d}")
    print(f"  ⏱ Total runtime: {total_minutes} min {total_seconds} sec ({total_duration:.1f}s)")
    print(f"{'='*80}\n")
    
    logger.info("="*80)
    logger.info("BATCH ENRICHMENT COMPLETED")
    logger.info(f"Processed: {len(processed_files)}, Total users: {total_users}")
    logger.info(f"Total runtime: {total_minutes} min {total_seconds} sec")
    logger.info("="*80)


def main():
    """Main entry point."""
    import argparse
    
    project_root = Path(__file__).parent
    
    startup_options_text = """
Startup options:
  1) Interactive single-file mode (default):
      %(prog)s

  2) Single file mode with explicit paths:
      %(prog)s -i input.csv -o output.csv

  3) Batch mode:
      %(prog)s --batch

  4) Batch mode with custom folders:
      %(prog)s --batch --input-dir exports/splitted --output-dir exports/enriched --report exports/enrichment_report_msgraph.md

  5) Show full help:
      %(prog)s --help

  Note (single file mode):
      Output file must be in the same folder as input file
      and must use a different filename.
"""

    parser = argparse.ArgumentParser(
        description='Enriches CSV with AD security group members (MICROSOFT GRAPH API)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚡ MICROSOFT GRAPH API:
  Uses Azure AD / Entra ID instead of on-premises PowerShell.
  Batch optimization for best performance.

Examples:
    Interactive single-file mode (default):
    %(prog)s
  
    Single file with explicit paths:
    %(prog)s -i input.csv -o output.csv

    Batch processing:
        %(prog)s --batch
        """
    )

    parser.add_argument('-i', '--input', help='Input CSV file')
    parser.add_argument('-o', '--output', help='Output CSV file')
    parser.add_argument('--batch', action='store_true', help='Batch mode')
    parser.add_argument('--input-dir', help='Input directory (default: exports/splitted)')
    parser.add_argument('--output-dir', help='Output directory (default: exports/enriched)')
    parser.add_argument('--report', help='Report file (default: exports/enrichment_report_msgraph.md)')
    
    args = parser.parse_args()

    print(startup_options_text % {'prog': parser.prog})
    
    if not args.input and not args.output and not args.batch:
        print("⚡ MICROSOFT GRAPH API - Interactive single-file mode\n")
    
    if args.batch:
        input_dir = Path(args.input_dir) if args.input_dir else project_root / "exports" / "splitted"
        output_dir = Path(args.output_dir) if args.output_dir else project_root / "exports" / "enriched"
        report_file = Path(args.report) if args.report else project_root / "exports" / "enrichment_report_msgraph.md"
        
        batch_process(input_dir, output_dir, report_file)
        return

    if not args.input or not args.output:
        print("\nSingle file mode requires input and output paths.")
        print("Missing values will be asked interactively.")
        prompted_input, prompted_output = prompt_for_single_file_paths(project_root, args.input, args.output)
        args.input = str(prompted_input)
        args.output = str(prompted_output)

    input_path = Path(args.input)
    output_path = Path(args.output)

    if output_path.parent != input_path.parent:
        print("✗ Output file must be in the same folder as input file.")
        print(f"  Input folder:  {input_path.parent}")
        print(f"  Output folder: {output_path.parent}")
        sys.exit(1)

    if output_path.name == input_path.name:
        print("✗ Output filename must be different from input filename.")
        print(f"  Input file:  {input_path.name}")
        print(f"  Output file: {output_path.name}")
        sys.exit(1)
    
    logger = setup_logging()
    obs_logger, obs_file = setup_observations_log()
    
    process_csv(str(input_path), str(output_path), logger=logger, obs_logger=obs_logger)
    print(f"✓ Done! Enriched CSV: {output_path}")
    print(f"✓ Observations Log: {obs_file}\n")


if __name__ == "__main__":
    main()
