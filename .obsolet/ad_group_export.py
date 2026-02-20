"""
AD Group User Export Tool
Liest Benutzer einer Active Directory Gruppe aus und exportiert diese.
"""

import subprocess
import argparse
import csv
import json
from datetime import datetime


def get_ad_group_members(group_name, all_attributes=False):
    """
    Liest alle Mitglieder einer AD-Gruppe aus via PowerShell ADSI.
    
    Args:
        group_name: Name der AD-Gruppe
        all_attributes: Wenn True, werden alle verfügbaren Attribute exportiert
        
    Returns:
        Liste von Dictionaries mit Benutzerinformationen
    """
    members = []
    
    # PowerShell Boolean korrekt setzen
    ps_all_attrs = "$true" if all_attributes else "$false"
    
    # PowerShell Skript zum Auslesen der Gruppenmitglieder
    ps_script = f'''
$ErrorActionPreference = "Stop"
try {{
    # Domain Root abrufen
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $root = $domain.GetDirectoryEntry()
    
    # Searcher für Gruppe erstellen
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $root
    $searcher.Filter = "(&(objectCategory=group)(cn={group_name}))"
    $searcher.PropertiesToLoad.Add("member") | Out-Null
    
    $group = $searcher.FindOne()
    
    if ($group -eq $null) {{
        Write-Error "Gruppe nicht gefunden"
        exit 1
    }}
    
    $members = $group.Properties["member"]
    
    $results = @()
    foreach ($memberDN in $members) {{
        try {{
            $userEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$memberDN")
            
            # Nur User, keine Gruppen
            if ($userEntry.SchemaClassName -eq "user") {{
                if ({ps_all_attrs}) {{
                    # Alle Attribute exportieren
                    $user = @{{}}
                    foreach ($prop in $userEntry.Properties.PropertyNames) {{
                        try {{
                            $value = $userEntry.Properties[$prop]
                            if ($value.Count -gt 0) {{
                                if ($value.Count -eq 1) {{
                                    $user[$prop] = $value[0]
                                }} else {{
                                    $user[$prop] = $value -join "; "
                                }}
                            }} else {{
                                $user[$prop] = ""
                            }}
                        }} catch {{
                            $user[$prop] = ""
                        }}
                    }}
                }} else {{
                    # Standard-Attribute (nur die 3 gewünschten Felder)
                    $user = @{{
                        User = if ($userEntry.Properties["userPrincipalName"].Count -gt 0) {{ $userEntry.Properties["userPrincipalName"][0] }} else {{ "" }}
                        Alias = if ($userEntry.Properties["sAMAccountName"].Count -gt 0) {{ $userEntry.Properties["sAMAccountName"][0] }} else {{ "" }}
                        "User Status" = if ($userEntry.Properties["userAccountControl"].Count -gt 0) {{ $userEntry.Properties["userAccountControl"][0] }} else {{ "" }}
                    }}
                }}
                $results += $user
            }}
            $userEntry.Dispose()
        }} catch {{
            Write-Warning "Fehler bei Mitglied $memberDN : $_"
        }}
    }}
    
    $results | ConvertTo-Json -Depth 3
    
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}}
'''
    
    try:
        # PowerShell ausführen
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", 
             "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " + ps_script],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        if result.returncode != 0:
            print(f"PowerShell Fehler: {result.stderr}")
            return members
        
        # JSON Ausgabe parsen
        if result.stdout.strip():
            data = json.loads(result.stdout)
            
            # Einzelnes Objekt in Liste umwandeln
            if isinstance(data, dict):
                data = [data]
            
            members = data
        
    except json.JSONDecodeError as e:
        print(f"Fehler beim Parsen der PowerShell Ausgabe: {e}")
        print(f"Ausgabe war: {result.stdout}")
    except Exception as e:
        print(f"Fehler beim Abrufen der Gruppenmitglieder: {e}")
    
    return members


def export_to_console(members, all_attributes=False):
    """Gibt Mitglieder auf der Konsole aus."""
    print(f"\n{'='*80}")
    print(f"Gefundene Benutzer: {len(members)}")
    print(f"{'='*80}\n")
    
    for i, member in enumerate(members, 1):
        print(f"{i}. {member.get('User', '')}")
        
        if all_attributes:
            # Alle Attribute anzeigen
            for key, value in sorted(member.items()):
                if key != 'User':
                    print(f"   {key}: {value}")
        else:
            # Standard-Felder (nur die 3 gewünschten)
            print(f"   Alias: {member.get('Alias', '')}")
            print(f"   User Status: {member.get('User Status', '')}")
        print("-" * 80)


def export_to_csv(members, filename):
    """Exportiert Mitglieder in CSV-Datei."""
    if not members:
        print("Keine Daten zum Exportieren vorhanden.")
        return
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8-sig') as csvfile:
            fieldnames = members[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=',')
            
            writer.writeheader()
            writer.writerows(members)
        
        print(f"\n✓ CSV-Export erfolgreich: {filename}")
        print(f"  {len(members)} Benutzer exportiert")
    except Exception as e:
        print(f"Fehler beim CSV-Export: {e}")


def export_to_json(members, filename):
    """Exportiert Mitglieder in JSON-Datei."""
    if not members:
        print("Keine Daten zum Exportieren vorhanden.")
        return
    
    try:
        export_data = {
            'export_date': datetime.now().isoformat(),
            'user_count': len(members),
            'users': members
        }
        
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
        
        print(f"\n✓ JSON-Export erfolgreich: {filename}")
        print(f"  {len(members)} Benutzer exportiert")
    except Exception as e:
        print(f"Fehler beim JSON-Export: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Export von Active Directory Gruppenmitgliedern',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  %(prog)s -g "IT-Abteilung"
  %(prog)s -g "Vertrieb" --csv ausgabe.csv
  %(prog)s -g "Marketing" --json ausgabe.json --csv ausgabe.csv
  %(prog)s -g "HR" --all-attributes --csv alle_attribute.csv
        """
    )
    
    parser.add_argument('-g', '--group', 
                       required=True,
                       help='Name der AD-Gruppe')
    
    parser.add_argument('--csv',
                       metavar='DATEI',
                       help='Export als CSV-Datei')
    
    parser.add_argument('--json',
                       metavar='DATEI', 
                       help='Export als JSON-Datei')
    
    parser.add_argument('--all-attributes',
                       action='store_true',
                       help='Exportiert alle verfügbaren AD-Attribute (sehr ausführlich)')
    
    args = parser.parse_args()
    
    print(f"\nLese Mitglieder der Gruppe '{args.group}'...")
    if args.all_attributes:
        print("  Modus: Alle verfügbaren AD-Attribute")
    
    # Gruppenmitglieder abrufen
    members = get_ad_group_members(args.group, args.all_attributes)
    
    if not members:
        print("\nKeine Mitglieder gefunden oder Gruppe existiert nicht.")
        return
    
    # Ausgabe auf Konsole
    export_to_console(members, args.all_attributes)
    
    # Optional: CSV Export
    if args.csv:
        export_to_csv(members, args.csv)
    
    # Optional: JSON Export
    if args.json:
        export_to_json(members, args.json)


if __name__ == "__main__":
    main()
