## Changelog

Python 3.x API for the next generation of the vFeed Vulnerability and Threat Database.

### 0.9.8
* Added a new method `get_packages` to `Classification` class. The method will return affected packages vendors, product names, versions and more information.
* Reflected the changes of `get_packages` addition on the following:
    * Updated JSON files with the addition of `packages` key under `classification` section. The `packages` key has a vendor section with multiple keys (product, version affected and condition)
    * Added new table `packages_db` in the SQLite database.
* Enhanced the `Search` class as follows:
    * Added a new method `search_cpe` to search per [CWE (Common Weakness Enumeration)](https://cwe.mitre.org). 
    * Updated the `pyvfeed` CLI to search using 3 arguments (cve, cpe and cwe) 
    * Code optimizated. 
* Updated `api_sample.py` to demonstate how to perform the following:
    * Call the `get_packages` in API mode
    * Search for CWE in API mode.
* Fixed `requirement.txt` to support the latest `PyYAML` version.
* Reflected the changes in documentation
* Regenerate the whole vFeed Professional Vulnerability Database alonside 'Sync & Use' private Github repositories.

### Beta 0.9.7
* Enhanced the support to the [MITRE’s Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK™)](https://attack.mitre.org/wiki/Main_Page). 3 new keys added :
    * Permission required (`permission_required`)
    * By passed defenses (`bypassed_defenses`)
    * data sources (`data_sources`)
* Regenerate the whole vFeed Professional Vulnerability Database alonside 'Sync & Use' private Github repositories.

### Beta 0.9.6
* Added the support to the [MITRE’s Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK™)](https://attack.mitre.org/wiki/Main_Page) initiative.
* Reflected the changes in the exported JSON files with the addition of `attack_mitre` key under `ranking` section.
* Updated CAPEC data with "mitigations". Changes reflected with addition of a new key `mitigations` under CAPEC `parameters` section.
* Modified key from `category` to `categorization` under `ranking` section.
* Regenerate the whole vFeed Professional Vulnerability Database alonside 'Sync & Use' private Github repositories.

### Beta 0.9.5
* Optimized the code and export performance
* Modified tag from `attack_id` to `attack_methods`

### Beta 0.9.4
* Added a basic search module for CVEs and CPEs.
* Code clean and fix.
* Reflected the changes in documentation

### Beta 0.9.3
* Add support to third-party plugins. (Still in beta)
* Reflected the changes in documentation

### Beta 0.9.2
* Fixed `api_sample.py`
* Completed the `API reference` documentation

### Beta 0.9.1
* Standarized the API JSON responses
* Added `api_sample.py` to demonstate how to use pyvfeed in API mode
* Cleaned the code
* Reflected the changes in documentation

#### Beta 0.9 - Initial release
* First commit
* Sources dataset in concordance with vFeed IO Patent.
* Support to Amazon S3 Boto3
* Export to JSON & YAML
* Added documentation
