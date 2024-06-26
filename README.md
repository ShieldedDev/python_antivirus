# Simple Antivirus Program

## Overview :

This project is a simple antivirus program written in Python. It scans files and directories for known malware using hash-based detection and heuristic analysis. Detected malicious files are quarantined to a specified directory. This script is designed for educational purposes and basic malware detection demonstrations.

## Features :

- **Hash-Based Detection**: Detects files with known malware hashes.
- **Heuristic Analysis**: Detects files with suspicious patterns.
- **Quarantine**: Moves detected malicious files to a quarantine directory.
- **Logging**: Logs scan results and actions for review.

## Installation :

### Prerequisites :

- Python 3.6 or higher
- `pyfiglet` library for banner display

### Install Required Libraries :

```bash
pip install pyfiglet
pip install python-magic-bin
```
## Usage :
```bash
  git clone https://github.com/ShieldedDev/python_antivirus
  cd python_antivirus
```

## Run the Script :
```bash
  python antivirus.py <path-to-scan>
```
## Example :
  ```bash
  python antivirus.py /path/to/scan
```

## Script Details : 
1. **Banner Display:**  Displays a banner using `pyfiglet`.
2. **Hash Calculation:** Calculates the SHA-256 hash of each file.
3. **Heuristic Analysis:** Searches for suspicious patterns in file content.
4. **Malware Detection:** Compares file hashes against a database of known malware hashes.
5. **Quarantine:** Moves detected malicious files to the quarantine directory.
6. **Logging:** Logs scan results and actions to `logs.log`.

## Example Output :
```bash
  python antivirus.py Files
    _          _   ___     ___
   / \   _ __ | |_(_) \   / (_)_ __ _   _ ___
  / _ \ | '_ \| __| |\ \ / /| | '__| | | / __|
 / ___ \| | | | |_| | \ V / | | |  | |_| \__ \
/_/   \_\_| |_|\__|_|  \_/  |_|_|   \__,_|___/


Malware detected (by heuristic): Files\file
File quarantined: Files\file

Malware detected (by hash): Files\infectious_file
File quarantined: Files\infectious_file

Malware detected (by hash): Files\malware
File quarantined: Files\malware

Malware detected (by hash): Files\trojan
File quarantined: Files\trojan

Malware detected (by hash): Files\virus
File quarantined: Files\virus

 See logs file for more details
```

## Quarantine Directory :
Detected malicious files are moved to the Quarantined_Files directory. Ensure this directory exists or the script will create it automatically.

## Logging :
All actions and results are logged to logs.log for review. Check this file for detailed information about each scan.

## Disclaimer :
This script is for educational purposes only. It is not a replacement for professional antivirus software. Use it responsibly and at your own risk.
