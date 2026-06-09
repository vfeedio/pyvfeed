<h1 align="center">
    <img align="left" width="300" height="100" src="https://vfeed.io/wp-content/uploads/2019/11/logo_transparent.png" alt="vfeed"/>
    <br />
    <p style="color: #808080; text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.5);"><br /><br />
    pyvfeed - Python CLI for vFeed Vulnerability and Threat Intelligence
    </p>
</h1>

`pyvfeed` is a Python command-line tool for querying the vFeed correlated vulnerability and threat intelligence database. It produces structured JSON output covering CVE information, CVSS 2/3/4 scoring, EPSS, KEV, MITRE ATT&CK, advisories, exploits, patches, detection rules, and more.

---

## Requirements

- Python 3.9+
- `boto3` — licensed DB updates via AWS S3
- `pyyaml` — YAML export support
- `urllib3` / stdlib `urllib` — demo DB download

Install all dependencies:

```bash
pip install -r requirements.txt
```

---

## Quick Start

### 1. Download the demo DB

Downloads the demo vFeed DB and checks for updates automatically.

```bash
python pyvfeed.py --download-demo-db
[+] Checking demo DB update status ...
    [-] Fetching remote checksum from '...' ...
    [-] Remote checksum: a3f1...
    [-] Downloading demo DB 'vfeed.db.tgz' ...
    [-] Unpacking ...
[+] Cleaning tmp downloads ...
```

### 2. Set the DB file permanently

Save the DB path so every subsequent command uses it without needing `--db`:

```bash
python pyvfeed.py --set-dbfile /path/to/vfeed.db
[+] DB file saved to /path/to/pyvfeed/.pyvfeedrc: /path/to/vfeed.db
```

This writes a `.pyvfeedrc` file in the project directory. All future runs pick it up automatically.

### 3. Override the DB for a single run

Use `--db` to point at a different database without changing `.pyvfeedrc`:

```bash
python pyvfeed.py --db /tmp/other.db --information CVE-2017-9805
```

**DB resolution order:** `common/config.py` → `.pyvfeedrc` → `--db`

---

## Database Management

### Show DB schema

```bash
python pyvfeed.py --schema
```

Prints all `CREATE TABLE` and `CREATE INDEX` statements from the SQLite3 DB.

### Update licensed DB

Requires valid subscription keys in `common/config.py`:

```bash
python pyvfeed.py --update
[+] Checking update status ...
    [-] Checksum verification a3f1...
    [-] Already updated
[+] Cleaning tmp downloads ...
```

If the local DB is out of date, it downloads and unpacks the latest version automatically.

### Version info

```bash
python pyvfeed.py --version
{
  "title": "Python CLI for vFeed Vulnerability and Threat Intelligence - Pro Edition",
  "build": "2.0.0",
  "support": "support@vfeed.io"
}
```

---

## Vulnerability Queries

All query commands accept a CVE or CPE identifier and return JSON.

### Information

Basic vulnerability metadata including NVD status and triage flags when available.

```bash
python pyvfeed.py --information CVE-2017-9805
{
  "information": {
    "description": [
      {
        "id": "CVE-2017-9805",
        "parameters": {
          "published": "2017-09-05T17:29Z",
          "modified": "2019-10-03T00:03Z",
          "summary": "The REST Plugin in Apache Struts 2.1.2 ...",
          "vuln_status": "Analyzed",
          "source_identifier": "security@apache.org",
          "has_exploits": true,
          "has_kev_cisa": true,
          "has_patches": true,
          "has_advisory": true,
          "risk_score": 0.94
        }
      }
    ],
    "references": [
      { "vendor": "MISC", "url": "https://..." }
    ]
  }
}
```

### Classification

CPE targets, affected packages and CWE weaknesses with MITRE ATT&CK ranking.

```bash
python pyvfeed.py --classification CVE-2017-9805
```

### Risk

CVSS 2, CVSS 3, CVSS 4 (when available), EPSS probability and CISA KEV catalog entry.

```bash
python pyvfeed.py --risk CVE-2017-9805
{
  "risk": {
    "cvss": {
      "cvss2": {
        "vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
        "base_score": "6.8",
        ...
      },
      "cvss3": {
        "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "base_score": "8.1",
        ...
      },
      "cvss4": {
        "vector": "CVSS:4.0/AV:N/AC:L/...",
        "base_score": "9.3",
        ...
      }
    },
    "epss": {
      "probability": 0.95975,
      "percentile": 0.99987
    },
    "kev": {
      "id": "CISA:BOD 22-01",
      "parameters": {
        "date_added": "2021-11-03",
        "date_due": "2022-05-03",
        "name": "Apache Struts Multiple Versions Remote Code Execution Vulnerability",
        "vendor": "Apache",
        "product": "Struts",
        "required_action": "Apply updates per vendor instructions.",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
      }
    }
  }
}
```

> `cvss4` is omitted when no CVSS 4.0 entry exists for the CVE.

### Advisory

Top advisories from the advisory database for a given CVE.

```bash
python pyvfeed.py --advisory CVE-2017-9805
[
  {
    "type": "vendor",
    "source": "Apache",
    "id": "S2-052",
    "link": "https://cwiki.apache.org/confluence/display/WW/S2-052"
  },
  ...
]
```

### MITRE CWE and ATT&CK

CWE weaknesses and resolved ATT&CK techniques via the CVE → CWE → CAPEC → ATT&CK chain.

```bash
python pyvfeed.py --mitre CVE-2017-9805
{
  "cve_id": "CVE-2017-9805",
  "weaknesses": [
    {
      "cwe_id": "CWE-502",
      "title": "Deserialization of Untrusted Data",
      "class": "weakness",
      "url": "https://cwe.mitre.org/data/definitions/502.html",
      "attack_techniques": [
        {
          "id": "T1059",
          "name": "Command and Scripting Interpreter",
          "tactic": "execution",
          "description": "...",
          "url": "https://attack.mitre.org/techniques/T1059/"
        }
      ]
    }
  ]
}
```

### Inspection

Remote and local vulnerability scanner signatures (Nessus, OpenVAS, etc.).

```bash
python pyvfeed.py --inspection CVE-2017-9805
```

### Exploitation

Exploits and PoCs from ExploitDB, Metasploit and other sources.

```bash
python pyvfeed.py --exploitation CVE-2017-9805
```

### Defense

Vendor patches, security bulletins, IDS/IPS rules (Snort, Suricata, Juniper).

```bash
python pyvfeed.py --defense CVE-2017-9805
```

### Export

Export all metadata for a CVE to a JSON file in the configured export path.

```bash
python pyvfeed.py --export CVE-2017-9805
# Produces: CVE-2017-9805.json
```

---

## Search

### Search by CVE

Returns basic info and any available exploits.

```bash
python pyvfeed.py --search cve CVE-2017-9805
```

### Search by CPE

Accepts both CPE 2.2 (`cpe:/`) and CPE 2.3 (`cpe:2.3:`) formats.

```bash
python pyvfeed.py --search cpe "cpe:2.3:a:apache:struts:2.3.5:*:*:*:*:*:*:*"
python pyvfeed.py --search cpe "cpe:/a:apache:struts:2.3.5"
```

### Search by CWE

Returns all CVEs associated with a CWE identifier.

```bash
python pyvfeed.py --search cwe CWE-502
{
  "id": "CWE-502",
  "parameters": {
    "title": "Deserialization of Untrusted Data",
    "class": "weakness",
    "url": "https://cwe.mitre.org/data/definitions/502.html"
  },
  "vulnerability": [
    "CVE-2017-9805",
    "CVE-2019-0232",
    ...
  ]
}
```

---

## Language Vulnerabilities

List CVEs related to a programming language, enriched with CVSS scores and metadata.

```bash
python pyvfeed.py --lang python
python pyvfeed.py --lang cpp
python pyvfeed.py --lang javascript
python pyvfeed.py --lang golang
python pyvfeed.py --lang java
```

Example output entry:

```json
{
  "cve_id": "CVE-2021-3177",
  "summary": "Python 3.x through 3.9.1 has a buffer overflow ...",
  "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cpe23_id": "cpe:2.3:a:python:python:3.9.0:*:*:*:*:*:*:*",
  "cvss4_vector": "CVSS:4.0/AV:N/AC:L/...",
  "cvss4_base": "9.3",
  "vuln_status": "Analyzed",
  "has_exploits": true,
  "risk_score": 0.87
}
```

---

## Package Vulnerabilities

List CVEs affecting a specific package, with an optional version range filter.

```bash
# All versions
python pyvfeed.py --pkgs wordpress

# Specific version range
python pyvfeed.py --pkgs openssl 1.0.1
```

---

## Configuration

### common/config.py

Default database and export paths, and subscription keys for licensed DB updates:

```python
database = {
    "file": "vfeed.db",
    "path": "./"
}

export = {"path": "/tmp"}

subscription = {
    "access_key": "YOUR_ACCESS_KEY",
    "secret_key": "YOUR_SECRET_KEY",
    "plan":       "YOUR_PLAN"
}
```

### .pyvfeedrc

Created automatically by `--set-dbfile`. Stored in the project directory:

```json
{
  "dbfile": "/path/to/vfeed.db"
}
```

---

## Full Help

```bash
python pyvfeed.py --help

usage: pyvfeed [-h] [--db FILE] [--set-dbfile FILE] [--schema] [--update]
               [--download-demo-db] [--information CVE|CPE]
               [--classification CVE|CPE] [--risk CVE|CPE]
               [--inspection CVE|CPE] [--exploitation CVE|CPE]
               [--defense CVE|CPE] [--advisory CVE] [--mitre CVE]
               [--export CVE|CPE] [--search TYPE ID] [--lang LANGUAGE]
               [--pkgs PACKAGE [PACKAGE ...]] [--version] [--plugin NAME TARGET]

Python CLI for vFeed Vulnerability and Threat Intelligence - Pro Edition

database:
  --db FILE            SQLite3 DB file to use (overrides config and .pyvfeedrc)
  --set-dbfile FILE    Permanently save DB file path to .pyvfeedrc
  --schema             Print DB schema to stdout
  --update             Update the vFeed database
  --download-demo-db   Download demo vFeed DB

vulnerability queries:
  --information CVE|CPE
  --classification CVE|CPE
  --risk CVE|CPE
  --inspection CVE|CPE
  --exploitation CVE|CPE
  --defense CVE|CPE
  --advisory CVE
  --mitre CVE
  --export CVE|CPE

search:
  --search TYPE ID     Search by type (cpe, cve, cwe) and identifier
  --lang LANGUAGE      List CVEs for a language
  --pkgs PACKAGE ...   List CVEs for a package and optional version

miscellaneous:
  --version            Show version and build info
  --plugin NAME TARGET Load and run a third-party plugin
```

<br/>Copyright (C) vFeed IO
    <a href="https://vfeed.io">
    <img align="center" width="85" src="https://img.shields.io/badge/vFeed-8A2BE2" alt="vFeed"/></a>
2026.
