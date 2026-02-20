# AD Users and Groups Enrichment Tool

This project reads AD group information from CSV files, resolves group IDs via Microsoft Graph API, retrieves all group members (including pagination), and writes enriched output files for downstream analysis.

## Program Purpose

The script `get_users_and_groups_from_ad.py` is used to:

- read input rows containing `persona`, `AD Security Group`, and `DocUnit`
- resolve each group against Microsoft Graph (technical and non-technical names)
- maintain/update a local mapping file for resolved groups
- retrieve group members and enrich rows with user details
- create reports and logs for traceability

## Prerequisites

### 1) Python and dependencies

- Python 3.10+ recommended
- Install dependencies from `requirements.txt`

Example:

```powershell
pip install -r requirements.txt
```

### 2) Bearer token in `.env`

Create or update `.env` in the project root with:

```env
BEARER_TOKEN=<your_access_token>
USE_PROXY=true
NO_PROXY=false
```

### 3) Input, mapping, output files

#### Input file (required)

- Typical file: `persona_ad_sg_mapping.csv`
- Required columns:
	- `persona`
	- `AD Security Group`
	- `DocUnit`

#### Mapping file (required, auto-updated)

- File: `conf/group_id_mapping.csv`
- Required header:

```csv
no,displayName,onPremisesSamAccountName,mailNickname,id
```

The script appends new mapping rows and logs unresolved groups with error markers.

#### Output file(s)

- Single run output: user-defined via `-o`
- Batch output folder: `exports/enriched/`
- Enriched output columns:
	- `persona`
	- `AD Security Group`
	- `DocUnit`
	- `User`
	- `Alias`
	- `User Status`

## Folder Structure and Expected Files

Main structure in this project:

```text
iqms_ad_export/
├─ get_users_and_groups_from_ad.py              # Main program
├─ README.md                                    # This documentation
├─ requirements.txt                             # Python dependencies
├─ .env                                         # Runtime environment values (token, proxy)
├─ conf/
│  └─ group_id_mapping.csv                      # Group mapping cache, updated by script
├─ docs/
│  ├─ microsoft_graph_api_anforderungen.md      # Graph API and permission details
│  └─ graph-explorer-access-token.png            # Screenshot for Graph Explorer token tab
├─ exports/
│  ├─ splitted/                                 # Batch input CSV files
│  └─ enriched/                                 # Batch output CSV files
├─ logs/
│  └─ get_users_and_groups_from_ad_*.log        # Timestamped execution logs per run
└─ reports/
	 └─ observations_from_get_users_and_groups_*.md  # Timestamped observations per run
```

## How to Run

### Single file mode

```powershell
python get_users_and_groups_from_ad.py -i persona_ad_sg_mapping.csv -o test_output.csv
```

### Batch mode

```powershell
python get_users_and_groups_from_ad.py --batch
```

Optional batch arguments:

```powershell
python get_users_and_groups_from_ad.py --batch --input-dir exports/splitted --output-dir exports/enriched --report exports/enrichment_report_msgraph.md
```

## How to Get the Bearer Token

For testing, you can obtain a temporary token from Microsoft Graph Explorer:

1. Open https://developer.microsoft.com/en-us/graph/graph-explorer
2. Sign in with your organization account
3. Run a simple query, e.g. `https://graph.microsoft.com/v1.0/me`
4. Open the **Access token** tab
5. Copy the token
6. Paste it into `.env` as `BEARER_TOKEN=<token>`

Reference image:

![Graph Explorer - Access Token Tab](docs/graph-explorer-access-token.png)

Important notes:

- Graph Explorer tokens are temporary and expire quickly.
- When expired, the script will fail with 401 errors.
- For stable automation, use app registration/service principal and proper OAuth flow.

For enterprise setup details (tenant/app registration, permissions, consent, proxy), see:

- `docs/microsoft_graph_api_anforderungen.md`
