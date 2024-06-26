import argparse
import os
import hashlib
import shutil
import re
import logging
import pyfiglet

def banner():
    banner = pyfiglet.figlet_format("AntiVirus")
    print(banner)

# Initialize logging
logging.basicConfig(filename='logs.log', level=logging.INFO)

# Database of malware hashes (Example)
database = {
    '3aed37043fac3afaa69c36191a63494d5630deb996fc61b437524cddd55326f6', # Malicious
    '2898a07b2cf23dda8530b14b6aa522e67b002886d170c02219acc3598fdb50f3', # Virus
    '7aca6784a90c48650922820554679059fcc26abf90a34a3b0b4497ec6f9815d7', # Trojan
    '18028bd173f32e98ae9f3733fe3037403777cfd7e3fd4f7dc57ebf32daa90480'  # Infected File
}

# Quarantined file's directory
quarantine_dir = 'Quarantined_Files'
if not os.path.exists(quarantine_dir):
    os.makedirs(quarantine_dir)

def get_hash(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
        sha256_hash = hashlib.sha256(file_data).hexdigest()
    return sha256_hash

def heuristic_analysis(file_path):  
    with open(file_path, 'r', errors='ignore') as file:
        content = file.read()
    # Example heuristic: Look for a suspicious pattern (this should be more sophisticated)
    if re.search(r'suspicious_pattern', content, re.IGNORECASE):
        return True
    return False
    
def quarantine_file(file_path, quarantine_dir):
    try:
        shutil.move(file_path, quarantine_dir)
        print(f'File quarantined: {file_path}')
        logging.info(f'File quarantined: {file_path}')
    except Exception as e:
        print(f'Error quarantining file {file_path}: {e}')
        logging.error(f'Error quarantining file {file_path}: {e}')

def scan_file(file_path):
    try:
        file_hash = get_hash(file_path)  # Pass file_path to get_hash
        logging.info(f'Scanning file: {file_path}')
        
        if file_hash in database:
            print(f'Malware detected (by hash): {file_path}')
            logging.warning(f'Malware detected (by hash): {file_path}')
            quarantine_file(file_path, quarantine_dir)
        elif heuristic_analysis(file_path):
            print(f'Malware detected (by heuristic): {file_path}')
            logging.warning(f'Malware detected (by heuristic): {file_path}')
            quarantine_file(file_path, quarantine_dir)
        else:
            print(f'File clean: {file_path}')
            logging.info(f'File clean: {file_path}')
    except Exception as e:
        print(f'Error scanning file {file_path}: {e}')
        logging.error(f'Error scanning file {file_path}: {e}')

def scan_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Simple Antivirus Program")
    parser.add_argument('path', help='Path of file or directory to scan')
    args = parser.parse_args()

    if os.path.isdir(args.path):
        scan_directory(args.path)
    elif os.path.isfile(args.path):
        scan_file(args.path)
    else:
        print("Invalid path")
        logging.error("Invalid path provided")

    print("\n See logs file for more details")

if __name__ == "__main__":
    main()
