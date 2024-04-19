import csv, json, requests, re, time, sqlite3, importlib.util, sys, argparse
from datetime import datetime
from bs4 import BeautifulSoup

print('Starting cve.nvd.gov Web Scapper!') 

countPythonRelated = 0

# Set up argument parser
parser = argparse.ArgumentParser(description='Do NOT Download and extract main.zip from CVE.org website.')
parser.add_argument('--nodownload', action='store_true',
                    help='If set, the script will NOT download and extract the main.zip file (useful to used previously downloaded files).')

# Parse command-line arguments
args = parser.parse_args()

def load_external_module(module_path, module_name):
    """
    Dynamically load a module from the given path.
    """
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

vaitp_db = load_external_module("0_vaitp_db.py","vaitp_db")
    
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}

def extract_vulnerabilities(json_data):
    global countPythonRelated
    vulnerabilities = json_data.get("vulnerabilities", [])
    
    for vulnerability in vulnerabilities:
        countPythonRelated = countPythonRelated + 1
        cve_data = vulnerability.get("cve", {})
        cve_id = cve_data.get("id", "N/A")
        publish_date = cve_data.get("published", "N/A")
        
        # Convert the date to the desired format
        if publish_date != "N/A":
            publish_date = datetime.strptime(publish_date, "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%d")
        
        descriptions = cve_data.get("descriptions", [])
        summary = descriptions[0]["value"].replace('\n', ' ') if descriptions else "N/A"
        
        metrics = vulnerability.get("metrics", {})
        cvss_metric = metrics.get("cvssMetricV2", [{}])[0]
        score = cvss_metric.get("baseScore", "N/A")
        
        cwe_data = vulnerability.get("weaknesses", [{}])[0]
        cwe_id = cwe_data.get("description", [{}])[0].get("value", "N/A")
        
        # Write to CSV
        #csv_writer.writerow([description, cve_id, score, publish_date, cwe])

        # Check if we already have it in the db
        query = f"SELECT id FROM python_vulnerabilities WHERE cve LIKE '{cve_id}';"
        results = vaitp_db.execute_query(query)

        if results:
            print(f'Skipping known CVE: {cve_id}')
        else:
            print(f'Found an UNKOWN CVE: {cve_id}\n')
            #write to db
            vaitp_db.insert_vulnerability(summary, cve_id, score, publish_date, cwe_id)
            print(f'New vulnerability added to the database: {cve_id}\n')
            


if __name__ == "__main__":

    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Python' # This is pure JSON
    output_file_path = 'nvd_nist_gov.json'

    if not args.nodownload:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            json_data = response.json()
            with open(output_file_path, 'w') as file:
                json.dump(json_data, file, indent=4)
                
            print(f"JSON data downloaded and saved to {output_file_path}")
        else:
            exit(f"Failed to download JSON data. HTTP status code: {response.status_code}")
    else:
        print('Download flag not set. Skipping download.')


    print(f'Processing cve.nvd.gov list from: {output_file_path}')
    with open(output_file_path, 'r') as file:
        data = json.load(file)
        extract_vulnerabilities(data)
    print(f'Number of Python related entries found: {countPythonRelated}')

