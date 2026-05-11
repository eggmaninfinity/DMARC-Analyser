import os
import gzip
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from dependencies import folder_path, scanned_path

# TODO: 
#       refactor spf/dkim field checks into single loop that builds dict with all info


RED = "\033[31m"
BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
ORANGE = "\033[38;5;208m"
RESET = "\033[0m"

scanned = []
count = 0
SPFfails = 0
DKIMfails = 0
quarantine_count = 0
quarantined_emails = []

def main():

    if not os.path.exists(scanned_path):
        # Ensure the directory exists
        os.makedirs(os.path.dirname(scanned_path), exist_ok=True)
        
        # Create the empty file
        with open(scanned_path, 'w') as f:
            pass 
        print(f"Created {YELLOW}new{RESET} history file at:\n{ORANGE}{scanned_path}{RESET}")

    history = load_history()

    for filename in os.listdir(folder_path):
        global count
        file_path = os.path.join(folder_path, filename)
        
        
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


    quarantined_emails.sort(key=lambda x: x['date'])
    for email in quarantined_emails:

        print(f"{RED}Email Quarantined:{RESET} {email['filename']}")
        print(f"  Sending Server IP:   {email['server']}")
        print(f"  Date: {email['date']}")
        print(f"  Dispostion: {email['disposition']}")
        print(f"  SPF Result: {email['SPFresult']}")
        print(f"  SPF Domain: {email['actual_sender']}")
        print("-" * 30)

    domain_health = ((count - quarantine_count) / count) *100

    print(f'\nAll Done!\n{BLUE}{count}{RESET} DMARC reports scanned\n{RED}{quarantine_count}{RESET} Emails quarantined\n{GREEN}{domain_health:.2f}%{RESET} Domain Health')


    

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

            global quarantined_emails
            global quarantine_count
            quarantined = {}
            auth_results = record.find('auth_results')
            row = record.find('row')
            source_ip = row.findtext('source_ip')
            policy = row.find('policy_evaluated')
            disposition = policy.findtext('disposition')
            spf = auth_results.find('spf')
            spf_result = spf.findtext('result')
            domain = spf.findtext('domain')
            if disposition == 'quarantine':
                
                quarantine_count += 1
                quarantined = {
                    'date': date_str,
                    'filename': filename,
                    'server': source_ip, 
                    'disposition': disposition,
                    'SPFresult': spf_result,  
                    'actual_sender': domain                  
                }
                
                quarantined_emails.append(quarantined)
            '''
                
                print(f"{RED}Email Quarantined:{RESET} {filename}")
                print(f"  Sending Server IP:   {source_ip}")
                print(f"  Date: {date_str}")
                print(f"  Dispostion: {disposition}")
                print(f"  Actual Sender: {domain}")
                print("-" * 30)
            # Check SPF result
            #auth_results = record.find('auth_results')
            
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
                #if result == 'pass':
                    print(f"PASSED: {filename}")
                    print(f"  IP:   {source_ip}")
                    print(f"  Date: {date_str}")
                    print("-" * 30)
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

        '''              
            
    except Exception as e:
        print(f"Error parsing {filename}: {e}")

    
def append_to_history(filename):
    scanned.append(filename)


if __name__ == "__main__":
    main()


