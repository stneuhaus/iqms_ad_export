# Microsoft Graph API - Anforderungen für AD-Gruppen-Abfragen

**Dokument-Version:** 1.0
**Datum:** 07.02.2026
**Ziel:** REST-basierter Zugriff auf Active Directory Sicherheitsgruppen und deren Mitglieder

---

## Inhaltsverzeichnis

1. [Übersicht](#übersicht)
2. [Voraussetzungen](#voraussetzungen)
3. [Benötigte Informationen - Checkliste](#benötigte-informationen---checkliste)
4. [App-Registrierung in Azure AD](#app-registrierung-in-azure-ad)
5. [Erforderliche API-Permissions](#erforderliche-api-permissions)
6. [Authentifizierung](#authentifizierung)
7. [Python-Integration](#python-integration)
8. [API-Endpunkte und Beispiele](#api-endpunkte-und-beispiele)
9. [E-Mail-Vorlage für IT-Abteilung](#e-mail-vorlage-für-it-abteilung)
10. [Vergleich: Graph API vs. PowerShell](#vergleich-graph-api-vs-powershell)
11. [Troubleshooting](#troubleshooting)
12. [Wichtige Hinweise](#wichtige-hinweise)
13. [Weiterführende Links](#weiterführende-links)

---

## Übersicht

### Was ist Microsoft Graph API?

Microsoft Graph API ist eine einheitliche REST-API-Schnittstelle für den Zugriff auf Microsoft 365-Dienste, einschließlich Azure Active Directory. Sie ermöglicht programmatischen Zugriff auf:

- **Azure AD-Objekte** (Benutzer, Gruppen, Geräte)
- **Microsoft 365-Dienste** (Exchange, SharePoint, Teams)
- **Security & Compliance**
- **Weitere Microsoft-Cloud-Dienste**

### Warum Microsoft Graph API für AD-Abfragen?

**Vorteile:**

- ✅ **REST-basiert** - Standard HTTP/JSON, plattformunabhängig
- ✅ **Performant** - Batch-Anfragen möglich (bis zu 20 Requests parallel)
- ✅ **Gut dokumentiert** - Umfangreiche Microsoft-Dokumentation
- ✅ **SDKs verfügbar** - Python, C#, JavaScript, Java, etc.
- ✅ **Moderne Authentifizierung** - OAuth 2.0 mit Token-Management
- ✅ **Skalierbar** - Designt für große Datenmengen
- ✅ **Versioniert** - Stabile API-Versionen (v1.0, beta)

**Nachteile:**

- ⚠️ **Azure AD erforderlich** - Funktioniert nur mit Azure AD oder Hybrid-Setup
- ⚠️ **Initiale Setup-Komplexität** - App-Registrierung erforderlich
- ⚠️ **Permissions-Management** - IT-Admin muss Rechte erteilen
- ⚠️ **Rate Limits** - Throttling bei zu vielen Anfragen

---

## Voraussetzungen

### Technische Voraussetzungen

**Muss vorhanden sein:**

1. ☑️ **Azure Active Directory Tenant**

   - Ihr Unternehmen muss einen Azure AD Tenant haben
   - Alternative: Hybrid-Setup (On-Premises AD + Azure AD Connect)
2. ☑️ **Admin-Zugriff für App-Registrierung**

   - Ein IT-Administrator mit Berechtigung "Application Administrator" oder "Global Administrator"
   - Dieser Admin muss die App registrieren und Permissions erteilen
3. ☑️ **Netzwerk-Zugriff**

   - Zugriff auf `https://login.microsoftonline.com` (Authentifizierung)
   - Zugriff auf `https://graph.microsoft.com` (API-Endpunkt)
   - Eventuell Proxy-Konfiguration erforderlich

### Organisatorische Voraussetzungen

1. **IT Security Genehmigung**

   - Antrag für API-Zugriff auf AD-Daten
   - Begründung des Use Cases
   - Eventuell Security Review erforderlich
2. **Compliance & Datenschutz**

   - DSGVO-Konformität prüfen
   - Zweckbindung dokumentieren
   - Datenspeicherung klären

---

## Benötigte Informationen - Checkliste

### 1. Azure AD Tenant Information

**Was:** Eindeutige Identifikation Ihres Azure AD Tenants

**Format:**

```
Tenant ID (UUID):    12345678-1234-1234-1234-123456789abc
Tenant Name:         ihrefirma.onmicrosoft.com
Primary Domain:      ihrefirma.com
```

**Wo zu finden:**

- Azure Portal → Azure Active Directory → Overview
- PowerShell: `Get-AzureADTenantDetail`

**Beispiel-Anfrage:**

> "Bitte teilen Sie mir die **Tenant ID** unseres Azure AD Tenants mit."

---

### 2. App Registration (Application ID)

**Was:** Registrierte Anwendung in Azure AD, die API-Zugriff erhält

**Format:**

```
Application (Client) ID:  87654321-4321-4321-4321-cba987654321
Application Name:         AD-Group-Export-Tool
Object ID:                abcdef12-3456-7890-abcd-ef1234567890
```

**Wichtig:**

- Die IT-Abteilung muss diese App erstellen
- Siehe Abschnitt [App-Registrierung](#app-registrierung-in-azure-ad) für Details

**Beispiel-Anfrage:**

> "Bitte registrieren Sie eine neue App in Azure AD mit dem Namen **'AD-Group-Export-Tool'** und teilen Sie mir die **Application (Client) ID** mit."

---

### 3. Client Secret (Application Secret)

**Was:** Passwort/Geheimnis für die Anwendung zur Authentifizierung

**Format:**

```
Secret Value:       abc123~XYZ.def456-ghi789_jkl012
Secret ID:          12ab34cd-56ef-78gh-90ij-12kl34mn56op
Description:        "Production Secret"
Expires:            2027-02-07
```

**KRITISCH WICHTIG:**

- ⚠️ **Wird nur EINMAL angezeigt** bei Erstellung!
- ⚠️ Muss sicher gespeichert werden (z.B. Azure Key Vault, Password Manager)
- ⚠️ Hat ein Ablaufdatum (max. 24 Monate)
- ⚠️ Niemals in Code oder Git einchecken!

**Lebenszyklus:**

```
Erstellung → Anzeige (einmalig!) → Speicherung → Nutzung → Vor Ablauf erneuern
```

**Beispiel-Anfrage:**

> "Bitte erstellen Sie ein **Client Secret** für die App mit einer Gültigkeit von **24 Monaten** und senden Sie mir den Secret Value **einmalig per sicherem Kanal** (z.B. verschlüsselte E-Mail oder persönlich)."

---

### 4. API Permissions (Delegated vs. Application)

**Was:** Berechtigungen, die die App für Graph API benötigt

**Zwei Arten:**

#### A) **Delegated Permissions** (für User-Kontext)

- Benutzer meldet sich an
- App agiert im Namen des Benutzers
- **Nicht geeignet für unser Szenario** (Batch-Automatisierung)

#### B) **Application Permissions** (für App-Kontext) ✅

- App agiert selbstständig ohne Benutzer-Login
- Benötigt Admin Consent
- **Ideal für Batch-Verarbeitung**

**Benötigte Application Permissions:**

| Permission                     | Typ         | Begründung                                        |
| ------------------------------ | ----------- | -------------------------------------------------- |
| **Group.Read.All**       | Application | Alle AD-Gruppen lesen (Name, Beschreibung, etc.)   |
| **GroupMember.Read.All** | Application | Mitglieder von Gruppen auslesen                    |
| **User.Read.All**        | Application | Benutzerdetails lesen (UPN, Alias, Account-Status) |

**Optional (je nach Anforderung):**

| Permission                   | Typ         | Begründung                                                                 |
| ---------------------------- | ----------- | --------------------------------------------------------------------------- |
| **Directory.Read.All** | Application | Umfassender Lesezugriff auf Directory (wenn erweiterte Attribute benötigt) |
| **AuditLog.Read.All**  | Application | Falls Änderungshistorie relevant                                           |

**Admin Consent erforderlich:**

- ⚠️ Ein Global Administrator muss diese Permissions genehmigen
- ⚠️ Ohne Admin Consent funktioniert die App nicht

**Beispiel-Anfrage:**

> "Bitte erteilen Sie der App folgende **Application Permissions** mit **Admin Consent**:
>
> - Group.Read.All
> - GroupMember.Read.All
> - User.Read.All"

---

### 5. Authentifizierungs-Endpunkte

**Was:** URLs für OAuth 2.0 Token-Anfragen

**Format:**

```
Authority:           https://login.microsoftonline.com/{tenant-id}
Token Endpoint:      https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token
Scope:               https://graph.microsoft.com/.default
```

**Beispiel mit echter Tenant ID:**

```
Authority:           https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc
Token Endpoint:      https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/token
```

**Keine Anfrage nötig:**

- Diese sind standardisiert
- Werden aus Tenant ID abgeleitet

---

### 6. Netzwerk & Proxy-Konfiguration

**Was:** Firewall/Proxy-Einstellungen für Internetzugriff

**Zu klären:**

1. **Ist ein Proxy erforderlich?**

   ```
   Proxy URL:    http://proxy.ihrefirma.com:8080
   Auth:         NTLM / Basic / Keine
   Credentials:  Domain\Username + Password
   ```
2. **Sind Firewall-Regeln erforderlich?**

   ```
   Ausgehend erlauben:
   - login.microsoftonline.com:443 (HTTPS)
   - graph.microsoft.com:443 (HTTPS)
   ```
3. **Ist VPN erforderlich?**

   - Muss das Script aus dem Firmennetzwerk laufen?
   - Oder funktioniert es von extern (z.B. Home Office)?

**Beispiel-Anfrage:**

> "Benötigt der Zugriff auf Microsoft Graph API eine **Proxy-Konfiguration**? Falls ja, bitte die **Proxy-Details** bereitstellen. Müssen **Firewall-Regeln** für login.microsoftonline.com und graph.microsoft.com angepasst werden?"

---

### 7. Rate Limits & Quotas

**Was:** Beschränkungen für API-Anfragen

**Microsoft Standard-Limits:**

- **Throttling:** ~2000 Requests pro Sekunde pro App
- **Täglich:** Abhängig von Lizenz-Typ
- **Batch-Requests:** Max. 20 Requests pro Batch

**Zu klären:**

- Hat Ihre Organisation zusätzliche Limits?
- Gibt es dedizierte Quotas für Automatisierungs-Apps?

**Beispiel-Anfrage:**

> "Gibt es **unternehmens-spezifische Rate Limits** für Graph API-Zugriffe? Unsere Anwendung muss ca. **3700 AD-Gruppen** abfragen."

---

### 8. Support & Eskalation

**Was:** Ansprechpartner bei Problemen

**Zu erfragen:**

1. **Technischer Support:**

   - Wer ist zuständig für Graph API Issues?
   - Ticket-System oder direkte Kontaktperson?
2. **Monitoring:**

   - Wird API-Nutzung überwacht?
   - Gibt es Alerting bei ungewöhnlicher Aktivität?
3. **Security Incidents:**

   - An wen melden bei verdächtigen Token-Zugriffs-Versuchen?

**Beispiel-Anfrage:**

> "Wer ist der **zuständige Ansprechpartner** für Microsoft Graph API Support in unserem Unternehmen? Gibt es ein **Monitoring** für API-Zugriffe?"

---

## App-Registrierung in Azure AD

### Schritt-für-Schritt Anleitung (für IT-Abteilung)

**Diese Schritte muss ein Azure AD Administrator durchführen:**

#### 1. Azure Portal öffnen

```
URL: https://portal.azure.com
Anmeldung: Admin-Account
```

#### 2. Zur App-Registrierung navigieren

```
Azure Active Directory → App registrations → + New registration
```

#### 3. App-Details eingeben

| Feld                              | Wert                                                               |
| --------------------------------- | ------------------------------------------------------------------ |
| **Name**                    | `AD-Group-Export-Tool`                                           |
| **Supported account types** | `Accounts in this organizational directory only (Single tenant)` |
| **Redirect URI**            | `(Optional) - Leer lassen`                                       |

**→ Klick auf "Register"**

#### 4. Application ID notieren

Nach Erstellung wird angezeigt:

```
Application (client) ID:  87654321-4321-4321-4321-cba987654321
Directory (tenant) ID:    12345678-1234-1234-1234-123456789abc
Object ID:                abcdef12-3456-7890-abcd-ef1234567890
```

**→ Application ID KOPIEREN und sicher speichern**

#### 5. Client Secret erstellen

```
App → Certificates & secrets → + New client secret
```

| Feld                  | Wert                                |
| --------------------- | ----------------------------------- |
| **Description** | `Production Secret for AD Export` |
| **Expires**     | `24 months` (empfohlen)           |

**→ Klick auf "Add"**

**KRITISCH:**

- Secret Value wird **nur einmal** angezeigt!
- **SOFORT KOPIEREN** in sicheren Speicher!
- Format: `abc123~XYZ.def456-ghi789_jkl012`

#### 6. API Permissions hinzufügen

```
App → API permissions → + Add a permission → Microsoft Graph
```

**Auswahl:**

- `Application permissions` (NICHT Delegated!)

**Hinzufügen:**

- ☑️ `Group.Read.All`
- ☑️ `GroupMember.Read.All`
- ☑️ `User.Read.All`

**→ Klick auf "Add permissions"**

#### 7. Admin Consent erteilen

**WICHTIG:** Ohne diesen Schritt funktioniert nichts!

```
App → API permissions → Grant admin consent for [Tenant Name]
```

**→ Klick auf "Yes" im Bestätigungsdialog**

**Status-Spalte muss zeigen:**

```
✅ Granted for [Tenant Name]
```

#### 8. Zusammenfassung exportieren

**Diese Informationen an Entwickler weitergeben:**

```json
{
  "tenant_id": "12345678-1234-1234-1234-123456789abc",
  "client_id": "87654321-4321-4321-4321-cba987654321",
  "client_secret": "abc123~XYZ.def456-ghi789_jkl012",
  "authority": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc",
  "graph_endpoint": "https://graph.microsoft.com/v1.0",
  "permissions": [
    "Group.Read.All",
    "GroupMember.Read.All",
    "User.Read.All"
  ],
  "secret_expires": "2027-02-07"
}
```

---

## Erforderliche API-Permissions

### Detaillierte Beschreibung der Permissions

#### 1. Group.Read.All

**Was erlaubt es:**

- Lesen aller Gruppeninformationen im Directory
- Abrufen von Gruppennamen, Beschreibungen, Typ, etc.
- Suchen nach Gruppen via Filter

**API-Aufrufe die funktionieren:**

```http
GET /groups
GET /groups/{group-id}
GET /groups?$filter=displayName eq 'Gruppenname'
```

**Was NICHT erlaubt ist:**

- Gruppen erstellen/ändern/löschen
- Mitglieder hinzufügen/entfernen

#### 2. GroupMember.Read.All

**Was erlaubt es:**

- Lesen von Gruppenmitgliedschaften
- Auflisten aller Mitglieder einer Gruppe
- Transitive Mitgliedschaften (verschachtelte Gruppen)

**API-Aufrufe die funktionieren:**

```http
GET /groups/{group-id}/members
GET /groups/{group-id}/transitiveMembers
GET /users/{user-id}/memberOf
```

**Was NICHT erlaubt ist:**

- Mitglieder hinzufügen/entfernen

#### 3. User.Read.All

**Was erlaubt es:**

- Lesen von Benutzerinformationen
- Abrufen von UPN, DisplayName, Mail, AccountEnabled, etc.
- Suchen nach Benutzern

**API-Aufrufe die funktionieren:**

```http
GET /users
GET /users/{user-id}
GET /users?$filter=userPrincipalName eq 'user@domain.com'
```

**Was NICHT erlaubt ist:**

- Benutzer erstellen/ändern/löschen
- Passwörter zurücksetzen

### Warum Application Permissions statt Delegated?

| Aspekt                  | Delegated          | Application             |
| ----------------------- | ------------------ | ----------------------- |
| **User-Login**    | Erforderlich       | Nicht erforderlich ✅   |
| **Kontext**       | Im Namen des Users | Im Namen der App ✅     |
| **Batch-Jobs**    | Ungeeignet         | Ideal ✅                |
| **Admin Consent** | Optional           | Immer erforderlich      |
| **Use Case**      | Interaktive Apps   | Hintergrund-Services ✅ |

**Unser Szenario:** Batch-Verarbeitung ohne User-Interaktion → **Application Permissions**

---

## Authentifizierung

### OAuth 2.0 Client Credentials Flow

**Ablauf:**

```
1. App sendet Credentials an Token-Endpoint
   ↓
2. Azure AD validiert (Client ID + Secret)
   ↓
3. Azure AD gibt Access Token zurück (gültig 60-90 Min)
   ↓
4. App nutzt Token für Graph API Requests
   ↓
5. Token abgelaufen? → Neues Token anfordern (Schritt 1)
```

### Token-Request (Technische Details)

**HTTP Request:**

```http
POST https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id={client-id}
&scope=https://graph.microsoft.com/.default
&client_secret={client-secret}
&grant_type=client_credentials
```

**Response:**

```json
{
  "token_type": "Bearer",
  "expires_in": 3599,
  "ext_expires_in": 3599,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

### Token-Nutzung

**HTTP Request mit Token:**

```http
GET https://graph.microsoft.com/v1.0/groups
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

### Token-Sicherheit

**Best Practices:**

- ✅ Token nie in Logs ausgeben
- ✅ Token nicht in Code hard-coden
- ✅ Token nicht in Git committen
- ✅ Token nicht über unsichere Kanäle übertragen
- ✅ Token-Ablauf überwachen und automatisch erneuern
- ✅ Bei Compromise sofort Client Secret rotieren

---

## Python-Integration

### Installation

**Erforderliche Pakete:**

```bash
pip install msal requests
```

**Optional (für erweiterte Features):**

```bash
pip install msgraph-sdk azure-identity
```

### Minimales Code-Beispiel (mit MSAL)

```python
#!/usr/bin/env python3
"""
Microsoft Graph API - AD Group Export
"""

from msal import ConfidentialClientApplication
import requests
import json

# Konfiguration (von IT erhalten)
TENANT_ID = "12345678-1234-1234-1234-123456789abc"
CLIENT_ID = "87654321-4321-4321-4321-cba987654321"
CLIENT_SECRET = "abc123~XYZ.def456-ghi789_jkl012"  # NIEMALS IN GIT!

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["https://graph.microsoft.com/.default"]
GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"


def get_access_token():
    """
    Holt Access Token via Client Credentials Flow.
  
    Returns:
        str: Access Token oder None bei Fehler
    """
    app = ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET
    )
  
    result = app.acquire_token_for_client(scopes=SCOPES)
  
    if "access_token" in result:
        print(f"✓ Token erfolgreich geholt (gültig {result.get('expires_in', 0)} Sek)")
        return result["access_token"]
    else:
        print(f"✗ Token-Fehler: {result.get('error')}")
        print(f"  Beschreibung: {result.get('error_description')}")
        return None


def search_group_by_name(token, group_name):
    """
    Sucht AD-Gruppe nach Namen.
  
    Args:
        token: Access Token
        group_name: Name der Gruppe
      
    Returns:
        dict: Gruppen-Objekt oder None
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
  
    # Filter für exakte Namenssuche
    filter_query = f"displayName eq '{group_name}'"
    url = f"{GRAPH_ENDPOINT}/groups?$filter={filter_query}"
  
    response = requests.get(url, headers=headers)
  
    if response.status_code == 200:
        data = response.json()
        groups = data.get("value", [])
      
        if groups:
            return groups[0]  # Erste Übereinstimmung
        else:
            print(f"  Gruppe '{group_name}' nicht gefunden")
            return None
    else:
        print(f"  API-Fehler {response.status_code}: {response.text}")
        return None


def get_group_members(token, group_id):
    """
    Holt alle Mitglieder einer Gruppe.
  
    Args:
        token: Access Token
        group_id: ID der Gruppe
      
    Returns:
        list: Liste von User-Objekten
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
  
    url = f"{GRAPH_ENDPOINT}/groups/{group_id}/members"
    members = []
  
    while url:
        response = requests.get(url, headers=headers)
      
        if response.status_code == 200:
            data = response.json()
            members.extend(data.get("value", []))
          
            # Pagination: Nächste Seite?
            url = data.get("@odata.nextLink")
        else:
            print(f"  API-Fehler {response.status_code}: {response.text}")
            break
  
    return members


def main():
    """Hauptfunktion."""
  
    # 1. Token holen
    token = get_access_token()
    if not token:
        return
  
    # 2. Gruppe suchen
    group_name = "ef.u.iqms_qms_cqh_co_algeria_dz01"
    print(f"\nSuche Gruppe: {group_name}")
  
    group = search_group_by_name(token, group_name)
    if not group:
        return
  
    group_id = group["id"]
    print(f"✓ Gruppe gefunden: {group['displayName']} (ID: {group_id})")
  
    # 3. Mitglieder holen
    print(f"\nHole Mitglieder...")
    members = get_group_members(token, group_id)
  
    print(f"✓ {len(members)} Mitglied(er) gefunden:")
  
    for member in members:
        user_principal = member.get("userPrincipalName", "N/A")
        display_name = member.get("displayName", "N/A")
        account_enabled = member.get("accountEnabled", "N/A")
      
        status = "Enabled" if account_enabled else "Disabled"
      
        print(f"  - {display_name} ({user_principal}) - {status}")


if __name__ == "__main__":
    main()
```

### Erweiterte Features

#### Batch-Requests (Performance)

**20 Gruppen parallel abfragen:**

```python
def batch_get_groups(token, group_ids):
    """
    Holt mehrere Gruppen in einem Batch-Request.
  
    Args:
        token: Access Token
        group_ids: Liste von Group-IDs
      
    Returns:
        list: Gruppen-Objekte
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
  
    # Batch-Request erstellen (max 20 Requests)
    batch_requests = []
    for idx, group_id in enumerate(group_ids[:20]):
        batch_requests.append({
            "id": str(idx),
            "method": "GET",
            "url": f"/groups/{group_id}"
        })
  
    batch_payload = {
        "requests": batch_requests
    }
  
    url = f"{GRAPH_ENDPOINT}/$batch"
    response = requests.post(url, headers=headers, json=batch_payload)
  
    if response.status_code == 200:
        data = response.json()
        responses = data.get("responses", [])
      
        groups = []
        for resp in responses:
            if resp["status"] == 200:
                groups.append(resp["body"])
      
        return groups
    else:
        print(f"Batch-Fehler: {response.status_code}")
        return []
```

#### Token-Caching (Performance)

```python
import time

class TokenManager:
    """Verwaltet Access Tokens mit automatischer Erneuerung."""
  
    def __init__(self, tenant_id, client_id, client_secret):
        self.app = ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret
        )
        self.scopes = ["https://graph.microsoft.com/.default"]
        self.token = None
        self.expires_at = 0
  
    def get_token(self):
        """Holt Token (cached oder neu)."""
        now = time.time()
      
        # Token noch gültig?
        if self.token and now < self.expires_at - 60:  # 60s Puffer
            return self.token
      
        # Neues Token holen
        result = self.app.acquire_token_for_client(scopes=self.scopes)
      
        if "access_token" in result:
            self.token = result["access_token"]
            self.expires_at = now + result.get("expires_in", 3600)
            return self.token
        else:
            raise Exception(f"Token-Fehler: {result.get('error')}")
```

---

## API-Endpunkte und Beispiele

### Gruppen-Endpunkte

#### Alle Gruppen auflisten

```http
GET https://graph.microsoft.com/v1.0/groups
```

**Response:**

```json
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#groups",
  "value": [
    {
      "id": "group-id-1",
      "displayName": "ef.u.iqms_qms_cqh_co_algeria_dz01",
      "description": "QMS Group Algeria",
      "groupTypes": [],
      "securityEnabled": true
    }
  ]
}
```

#### Gruppe nach Namen suchen

```http
GET https://graph.microsoft.com/v1.0/groups?$filter=displayName eq 'ef.u.iqms_qms_cqh_co_algeria_dz01'
```

**URL-Encoding beachten:**

```
Leerzeichen → %20
& → %26
```

#### Spezifische Felder abrufen

```http
GET https://graph.microsoft.com/v1.0/groups?$select=id,displayName,mail,description
```

#### Paginierung (>100 Ergebnisse)

**Request:**

```http
GET https://graph.microsoft.com/v1.0/groups?$top=100
```

**Response enthält:**

```json
{
  "value": [...],
  "@odata.nextLink": "https://graph.microsoft.com/v1.0/groups?$skip=100"
}
```

**Python-Beispiel:**

```python
def get_all_groups(token):
    url = f"{GRAPH_ENDPOINT}/groups"
    all_groups = []
  
    while url:
        response = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        data = response.json()
      
        all_groups.extend(data.get("value", []))
        url = data.get("@odata.nextLink")  # Nächste Seite
  
    return all_groups
```

### Gruppen-Mitglieder Endpunkte

#### Mitglieder einer Gruppe

```http
GET https://graph.microsoft.com/v1.0/groups/{group-id}/members
```

**Response:**

```json
{
  "value": [
    {
      "@odata.type": "#microsoft.graph.user",
      "id": "user-id-1",
      "displayName": "Max Mustermann",
      "userPrincipalName": "max.mustermann@ihrefirma.com",
      "mail": "max.mustermann@ihrefirma.com",
      "accountEnabled": true
    }
  ]
}
```

#### Nur User-Felder abrufen

```http
GET https://graph.microsoft.com/v1.0/groups/{group-id}/members?$select=userPrincipalName,displayName,accountEnabled
```

#### Transitive Mitglieder (inkl. verschachtelte Gruppen)

```http
GET https://graph.microsoft.com/v1.0/groups/{group-id}/transitiveMembers
```

### Benutzer-Endpunkte

#### Benutzer-Details abrufen

```http
GET https://graph.microsoft.com/v1.0/users/{user-id}
```

#### Benutzer nach UPN suchen

```http
GET https://graph.microsoft.com/v1.0/users/{userPrincipalName}
```

**Beispiel:**

```http
GET https://graph.microsoft.com/v1.0/users/max.mustermann@ihrefirma.com
```

### Batch-Endpoint

#### Mehrere Requests kombinieren

```http
POST https://graph.microsoft.com/v1.0/$batch
Content-Type: application/json

{
  "requests": [
    {
      "id": "1",
      "method": "GET",
      "url": "/groups/group-id-1/members"
    },
    {
      "id": "2",
      "method": "GET",
      "url": "/groups/group-id-2/members"
    }
  ]
}
```

**Limits:**

- Max. 20 Requests pro Batch
- Max. 4 Batches parallel

---

## E-Mail-Vorlage für IT-Abteilung

### Vorlage 1: Initiale Anfrage

```
Betreff: Anfrage: Microsoft Graph API Zugang für AD-Gruppen-Export

Sehr geehrtes IT-Team,

ich entwickle ein Python-Automatisierungstool zur Abfrage von Active Directory 
Sicherheitsgruppen und deren Mitgliedern. Aktuell nutze ich PowerShell-Aufrufe, 
möchte aber auf die modernere Microsoft Graph API umstellen.

ANWENDUNGSFALL:
- Export von ~3700 AD-Sicherheitsgruppen mit Mitgliedern
- Batch-Verarbeitung für CSV-Reports
- Regelmäßige Aktualisierung der Berechtigungsmatrix

BENÖTIGTE INFORMATIONEN:

1. ☐ Azure AD Tenant ID
   - Eindeutige ID unseres Azure AD Tenants

2. ☐ App Registration
   - Bitte eine neue App registrieren: "AD-Group-Export-Tool"
   - Application (Client) ID bereitstellen
   - Client Secret erstellen (Gültigkeit: 24 Monate)

3. ☐ API Permissions (Application Permissions mit Admin Consent):
   - Group.Read.All
   - GroupMember.Read.All
   - User.Read.All

4. ☐ Netzwerk-Konfiguration
   - Proxy-Einstellungen (falls erforderlich)
   - Firewall-Freigaben für login.microsoftonline.com und graph.microsoft.com

5. ☐ Dokumentation
   - Internes Runbook für Graph API Nutzung
   - Ansprechpartner bei Support-Fragen

SICHERHEIT:
- Client Secret wird verschlüsselt in Azure Key Vault gespeichert
- Keine Schreibzugriffe erforderlich (nur Lesezugriff)
- Logging aller API-Aufrufe
- Compliance mit internen Security-Richtlinien

ZEITPLAN:
- Entwicklung: 2 Wochen
- Testing: 1 Woche
- Produktivbetrieb: ab 01.03.2026

Für Rückfragen stehe ich gerne zur Verfügung.
Eine detaillierte technische Dokumentation liegt diesem Antrag bei (siehe Anhang).

Mit freundlichen Grüßen
[Ihr Name]

Anhang: microsoft_graph_api_anforderungen.md
```

### Vorlage 2: Follow-Up nach App-Registrierung

```
Betreff: Follow-Up: Graph API App Registration - Credentials erforderlich

Hallo [IT-Admin Name],

vielen Dank für die App-Registrierung "AD-Group-Export-Tool".

Bitte senden Sie mir folgende Credentials per sicherem Kanal 
(verschlüsselte E-Mail oder persönlich):

ERFORDERLICH:
1. Tenant ID:           _______________________________
2. Application ID:      _______________________________
3. Client Secret:       _______________________________ (einmalig!)

BESTÄTIGUNG ERFORDERLICH:
☐ Admin Consent wurde erteilt für:
  - Group.Read.All
  - GroupMember.Read.All
  - User.Read.All

☐ Secret-Ablaufdatum notiert: __________
☐ Monitoring/Alerting konfiguriert: Ja/Nein

Nach Erhalt werde ich die Integration testen und Ihnen Feedback geben.

Vielen Dank!
[Ihr Name]
```

---

## Vergleich: Graph API vs. PowerShell

### Performance

| Metrik                               | PowerShell (aktuell) | Graph API (geplant) |
| ------------------------------------ | -------------------- | ------------------- |
| **Gruppen-Abfrage (1 Gruppe)** | ~2-3 Sek             | ~0.1-0.3 Sek        |
| **197 Gruppen**                | ~5-10 Min            | ~30-60 Sek          |
| **3700 Gruppen**               | ~3-6 Std             | ~5-15 Min           |
| **Batch-Fähigkeit**           | Nein (sequenziell)   | Ja (20 parallel)    |
| **Token-Overhead**             | Keiner               | Initial: 1-2 Sek    |

### Vorteile Graph API

| Aspekt                     | Vorteil                                   |
| -------------------------- | ----------------------------------------- |
| **Performance**      | 10-100x schneller                         |
| **Plattform**        | Funktioniert auf Linux/Mac/Windows        |
| **Deployment**       | Container-fähig, Cloud-ready             |
| **Monitoring**       | Azure Monitor Integration                 |
| **Fehlerbehandlung** | Strukturierte HTTP-Status-Codes           |
| **Pagination**       | Automatische Handhabung großer Datensets |

### Nachteile Graph API

| Aspekt                           | Nachteil                                    |
| -------------------------------- | ------------------------------------------- |
| **Setup-Komplexität**     | Initial höher (App-Registrierung)          |
| **Dependencies**           | Python-Pakete erforderlich (msal, requests) |
| **Azure AD Abhängigkeit** | Funktioniert nur mit Azure AD/Hybrid        |
| **Rate Limiting**          | Throttling möglich bei vielen Requests     |
| **Admin-Aufwand**          | IT muss Permissions managen                 |

### Wann welche Lösung?

**PowerShell bleiben, wenn:**

- ✅ Nur On-Premises AD (kein Azure AD)
- ✅ Sehr wenige Gruppen (<100)
- ✅ Einmalige/seltene Abfragen
- ✅ Keine IT-Unterstützung für App-Registrierung

**Graph API nutzen, wenn:**

- ✅ Azure AD oder Hybrid vorhanden
- ✅ Viele Gruppen (>500)
- ✅ Regelmäßige/automatisierte Abfragen
- ✅ Cloud-Deployment geplant
- ✅ Performance kritisch

---

## Troubleshooting

### Häufige Fehler und Lösungen

#### 1. Fehler: "invalid_client"

**Ursache:** Client ID oder Secret falsch

**Lösung:**

```python
# Prüfen:
print(f"Tenant ID: {TENANT_ID}")
print(f"Client ID: {CLIENT_ID}")
print(f"Secret beginnt mit: {CLIENT_SECRET[:10]}...")

# Sicherstellen:
# - Keine Leerzeichen am Anfang/Ende
# - Korrekte UUID-Format für IDs
# - Secret komplett kopiert (kann sehr lang sein!)
```

#### 2. Fehler: "insufficient_claims"

**Ursache:** Admin Consent fehlt

**Lösung:**

- IT-Admin muss in Azure Portal:
  - App → API permissions
  - → "Grant admin consent"

**Verifizierung:**

```python
# Status-Spalte muss zeigen:
✅ Granted for [Tenant Name]
```

#### 3. Fehler: "Authorization_RequestDenied"

**Ursache:** Fehlende Permission

**Lösung:**

```python
# Prüfen welche Permission fehlt:
# Im Error-Response steht: "Insufficient privileges to complete the operation"

# Benötigte Permissions hinzufügen:
# - Group.Read.All (für Gruppen)
# - GroupMember.Read.All (für Mitglieder)
# - User.Read.All (für User-Details)
```

#### 4. Fehler: "Timeout" / "ConnectTimeout"

**Ursache:** Netzwerk-/Proxy-Problem

**Lösung:**

```python
import requests

# Proxy konfigurieren:
proxies = {
    "http": "http://proxy.ihrefirma.com:8080",
    "https": "http://proxy.ihrefirma.com:8080"
}

response = requests.get(url, headers=headers, proxies=proxies, timeout=30)
```

#### 5. Fehler: "Too many requests" (429)

**Ursache:** Rate Limiting

**Lösung:**

```python
import time

def api_call_with_retry(url, headers, max_retries=3):
    for attempt in range(max_retries):
        response = requests.get(url, headers=headers)
      
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            print(f"Rate limit - warte {retry_after} Sekunden...")
            time.sleep(retry_after)
            continue
      
        return response
  
    raise Exception("Max retries erreicht")
```

#### 6. Fehler: "Resource not found" (404)

**Ursache:** Gruppe existiert nicht oder Namensfilter falsch

**Lösung:**

```python
# Statt:
filter_query = f"displayName eq '{group_name}'"  # Exakte Übereinstimmung!

# Besser (wenn Name nicht exakt bekannt):
filter_query = f"startsWith(displayName, '{group_prefix}')"
```

#### 7. Token-Ablauf während Verarbeitung

**Ursache:** Token läuft nach 60-90 Min ab

**Lösung:**

```python
class GraphAPIClient:
    def __init__(self, tenant_id, client_id, client_secret):
        self.token_manager = TokenManager(tenant_id, client_id, client_secret)
  
    def get_group_members(self, group_id):
        # Token automatisch erneuern
        token = self.token_manager.get_token()
      
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{GRAPH_ENDPOINT}/groups/{group_id}/members", headers=headers)
      
        return response.json()
```

---

## Wichtige Hinweise

### Sicherheit

#### Client Secret Verwaltung

**NIEMALS:**

- ❌ Secret in Git committen
- ❌ Secret in Code hard-coden
- ❌ Secret in Logs ausgeben
- ❌ Secret per unverschlüsselter E-Mail senden
- ❌ Secret in Klartext-Datei speichern

**STATTDESSEN:**

- ✅ Azure Key Vault nutzen
- ✅ Environment Variables
- ✅ Verschlüsselte Config-Dateien
- ✅ Credential Manager (Windows)
- ✅ Secrets Management Tools (HashiCorp Vault, etc.)

**Beispiel mit Environment Variables:**

```python
import os

# .env Datei (NICHT in Git!):
# GRAPH_TENANT_ID=12345678-1234-1234-1234-123456789abc
# GRAPH_CLIENT_ID=87654321-4321-4321-4321-cba987654321
# GRAPH_CLIENT_SECRET=abc123~XYZ.def456-ghi789_jkl012

TENANT_ID = os.environ.get("GRAPH_TENANT_ID")
CLIENT_ID = os.environ.get("GRAPH_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GRAPH_CLIENT_SECRET")

if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
    raise Exception("Graph API Credentials nicht gefunden!")
```

#### Secret-Rotation

**Ablaufdatum überwachen:**

```python
from datetime import datetime, timedelta

SECRET_EXPIRES = datetime(2027, 2, 7)
WARNING_DAYS = 30

days_until_expiry = (SECRET_EXPIRES - datetime.now()).days

if days_until_expiry <= WARNING_DAYS:
    print(f"⚠️ Client Secret läuft in {days_until_expiry} Tagen ab!")
    # E-Mail an Admin senden
```

### Compliance & Datenschutz

**DSGVO-Konformität:**

- ✅ Zweckbindung dokumentieren
- ✅ Datensparsamkeit (nur benötigte Felder abfragen)
- ✅ Aufbewahrungsfristen einhalten
- ✅ Zugriffsprotokolle führen
- ✅ Betroffenenrechte berücksichtigen

**Audit-Logging:**

```python
import logging
from datetime import datetime

# Setup
logging.basicConfig(
    filename=f"graph_api_audit_{datetime.now():%Y%m%d}.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Bei jedem API-Call:
logging.info(f"Graph API Call: GET /groups/{group_id}/members - User: {os.environ.get('USERNAME')}")
```

### Performance-Optimierung

**Batch-Verarbeitung nutzen:**

```python
# Statt 20 einzelne Requests:
for group_id in group_ids:
    get_group_members(token, group_id)  # 20 x Network Round-Trip

# Besser: 1 Batch-Request
batch_get_group_members(token, group_ids)  # 1 x Network Round-Trip
```

**Caching implementieren:**

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def get_user_details(token, user_id):
    """Cache User-Details (ändern sich selten)."""
    # ...
```

**Pagination effizient handeln:**

```python
def get_all_members_paginated(token, group_id, page_size=999):
    """Holt alle Mitglieder mit optimaler Page Size."""
    url = f"{GRAPH_ENDPOINT}/groups/{group_id}/members?$top={page_size}"
    # Max. 999 Elemente pro Seite reduziert Anzahl der Requests
```

---

## Weiterführende Links

### Offizielle Microsoft-Dokumentation

**Übersicht:**

- [Microsoft Graph API Overview](https://learn.microsoft.com/en-us/graph/overview)
- [Graph API Reference](https://learn.microsoft.com/en-us/graph/api/overview)

**Authentifizierung:**

- [Get access without a user](https://learn.microsoft.com/en-us/graph/auth-v2-service)
- [Client Credentials Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)

**Permissions:**

- [Permission Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Group Permissions](https://learn.microsoft.com/en-us/graph/api/resources/group)

**API-Endpunkte:**

- [Groups API](https://learn.microsoft.com/en-us/graph/api/resources/group)
- [Users API](https://learn.microsoft.com/en-us/graph/api/resources/user)
- [Group Members API](https://learn.microsoft.com/en-us/graph/api/group-list-members)

**Best Practices:**

- [Throttling &amp; Rate Limits](https://learn.microsoft.com/en-us/graph/throttling)
- [Paging](https://learn.microsoft.com/en-us/graph/paging)
- [Batching](https://learn.microsoft.com/en-us/graph/json-batching)
- [Error Handling](https://learn.microsoft.com/en-us/graph/errors)

**SDKs:**

- [Python SDK](https://github.com/microsoftgraph/msgraph-sdk-python)
- [MSAL Python](https://github.com/AzureAD/microsoft-authentication-library-for-python)

### Tools & Utilities

**Graph Explorer:**

- [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) - Interaktives Testing

**Postman Collection:**

- [Microsoft Graph Postman Collection](https://learn.microsoft.com/en-us/graph/use-postman)

**Code Samples:**

- [Microsoft Graph Python Samples](https://github.com/microsoftgraph/python-sample-console-app)

### Community & Support

**Foren:**

- [Microsoft Q&amp;A - Graph API](https://learn.microsoft.com/en-us/answers/tags/158/microsoft-graph)
- [Stack Overflow - microsoft-graph](https://stackoverflow.com/questions/tagged/microsoft-graph)

**Updates:**

- [Graph API Changelog](https://learn.microsoft.com/en-us/graph/changelog)
- [What&#39;s new in Graph API](https://learn.microsoft.com/en-us/graph/whats-new-overview)

---

## Anhang: Checkliste für IT-Abteilung

### Pre-Deployment Checklist

**Phase 1: Planung**

- ☐ Use Case dokumentiert
- ☐ Security Review durchgeführt
- ☐ DSGVO-Konformität geprüft
- ☐ Budget freigegeben (falls Azure-Kosten anfallen)

**Phase 2: App-Registrierung**

- ☐ App erstellt in Azure AD
- ☐ Application ID dokumentiert
- ☐ Client Secret erstellt (24 Monate Gültigkeit)
- ☐ Secret sicher an Entwickler übermittelt
- ☐ Ablaufdatum im Kalender markiert

**Phase 3: Permissions**

- ☐ Group.Read.All hinzugefügt
- ☐ GroupMember.Read.All hinzugefügt
- ☐ User.Read.All hinzugefügt
- ☐ Admin Consent erteilt
- ☐ Permissions verifiziert (Status: "Granted")

**Phase 4: Netzwerk**

- ☐ Proxy-Konfiguration dokumentiert (falls erforderlich)
- ☐ Firewall-Regeln erstellt (login.microsoftonline.com, graph.microsoft.com)
- ☐ VPN-Anforderungen geklärt

**Phase 5: Monitoring**

- ☐ Azure AD Sign-In Logs aktiviert
- ☐ Audit Logs für App-Zugriffe konfiguriert
- ☐ Alerting bei ungewöhnlicher Aktivität eingerichtet
- ☐ Runbook für Incident Response erstellt

**Phase 6: Dokumentation**

- ☐ Technische Dokumentation vervollständigt
- ☐ Ansprechpartner definiert (1st/2nd Level Support)
- ☐ Eskalationspfad dokumentiert
- ☐ Runbook für Secret-Rotation erstellt

**Phase 7: Testing**

- ☐ Entwickler hat Test-Zugriff erhalten
- ☐ Token-Acquisition getestet
- ☐ Beispiel-Abfragen erfolgreich
- ☐ Error-Handling validiert

**Phase 8: Go-Live**

- ☐ Production Credentials bereitgestellt
- ☐ Monitoring aktiv
- ☐ 1 Woche intensives Monitoring
- ☐ Feedback-Loop mit Entwickler etabliert

---

**Ende des Dokuments**

Bei Fragen oder Unklarheiten wenden Sie sich bitte an:

- Entwickler: [Ihr Name]
- IT-Admin: [IT-Ansprechpartner]
- Support: [Support-E-Mail/Ticket-System]
