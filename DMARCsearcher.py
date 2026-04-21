import os
import gzip
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from dependencies import folder_path, scanned_path

# TODO: refactor script in __main__ idiom - hard to parse atm
#       refactor spf/dkim field checks into single loop that builds dict with all info
#       fix history overwriting issue   

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
ORANGE = "\033[38;5;208m"
RESET = "\033[0m"


if not os.path.exists(scanned_path):
    # Ensure the directory exists
    os.makedirs(os.path.dirname(scanned_path), exist_ok=True)
    
    # Create the empty file
    with open(scanned_path, 'w') as f:
        pass 
    print(f"Created {YELLOW}new{RESET} history file at:\n{ORANGE}{scanned_path}{RESET}")


scanned = []
count = 0
SPFfails = 0
DKIMfails = 0

def load_history():
    with open(scanned_path, 'r') as history:
        previously_scanned = [line.strip() for line in history]

    return(previously_scanned)
        

def parse_dmarc_xml(file_content, filename):
    
    try:
        root = ET.fromstring(file_content)
        
        # Extract report metadata (Date)
        # Dates in DMARC are usually in Unix timestamps
        begin_date = root.findtext('.//report_metadata/date_range/begin')
        date_str = datetime.fromtimestamp(int(begin_date)).strftime('%Y-%m-%d') if begin_date else "Unknown Date"

        # Iterate through each 'record' in the XML
        for record in root.findall('record'):
            
            row = record.find('row')
            source_ip = row.findtext('source_ip')
            
            # Check SPF result
            auth_results = record.find('auth_results')
            for spf in auth_results.findall('spf'):
                result = spf.findtext('result')
                global SPFfails
                global DKIMfails
                if result == 'fail':
                    print(f"{RED}SPF HARD FAIL:{RESET} {filename}")
                    print(f"  IP:   {source_ip}")
                    print(f"  Date: {date_str}")
                    print(f"  Result: {result}")
                    print("-" * 30)
                    SPFfails  += 1
                if result != 'pass':
                    print(f"SPF FAILED: {filename}")
                    print(f"  IP:   {source_ip}")
                    print(f"  Date: {date_str}")
                    print(f"  Result: {result}")
                    print("-" * 30)
                    SPFfails  += 1
                '''if result == 'pass':
                    print(f"PASSED: {filename}")
                    print(f"  IP:   {source_ip}")
                    print(f"  Date: {date_str}")
                    print("-" * 30)'''
            for dkim in auth_results.findall('dkim'):
                result = dkim.findtext('result')
                if result == 'fail':
                    print(f"{RED}DKIM HARD FAIL:{RESET} {filename}")
                    print(f"  IP:   {source_ip}")
                    print(f"  Date: {date_str}")
                    print(f"  Result: {result}")
                    print("-" * 30)
                    DKIMfails  += 1
                if result != 'pass':
                    print(f"DKIM FAILED: {filename}")
                    print(f"  IP:   {source_ip}")
                    print(f"  Date: {date_str}")
                    print(f"  Result: {result}")
                    print("-" * 30)
                    DKIMfails += 1

                
            
    except Exception as e:
        print(f"Error parsing {filename}: {e}")

    
def append_to_history(filename):
    scanned.append(filename)

# Process files in the folder
for filename in os.listdir(folder_path):
    file_path = os.path.join(folder_path, filename)
    
    history = load_history()
    
    if filename not in history:
        count += 1
        
        # Handle .gz files
        if filename.endswith('.gz'):
            with gzip.open(file_path, 'rb') as f:
                parse_dmarc_xml(f.read(), filename)
                append_to_history(filename)
            
                
        # Handle .zip files
        elif filename.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as z:
                for xml_name in z.namelist():
                    with z.open(xml_name) as f:
                        parse_dmarc_xml(f.read(), filename)
                        append_to_history(filename)
                        
        # Handle raw .xml files
        elif filename.endswith('.xml'):
            with open(file_path, 'rb') as f:
                parse_dmarc_xml(f.read(), filename)
                append_to_history(filename)

if scanned:
    with open(scanned_path, 'a') as file:
        for entry in scanned:
            file.write(f'{entry}\n')

print(f'\nAll Done!\n{GREEN}{count}{RESET} DMARC reports scanned\n{RED}{SPFfails}{RESET} SPF issues detected\n{RED}{DKIMfails}{RESET} DKIM issues detected\n')