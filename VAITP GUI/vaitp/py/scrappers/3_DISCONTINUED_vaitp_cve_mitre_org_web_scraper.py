import csv, re, requests, argparse, importlib.util, sys, time, os, io
import xml.etree.ElementTree as ET
from datetime import datetime
from bs4 import BeautifulSoup
print(f'Starting VAITP cve.mitre.org Web Scraper!')

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}

countPythonRelated = 0

# Set up argument parser
parser = argparse.ArgumentParser(description='Do NOT Download and extract main.zip from CVE.org website.')
parser.add_argument('--nodownload', action='store_true',
                    help='If set, the script will NOT download and extract the main.zip file (useful to used previously downloaded files).')

# Parse command-line arguments
args = parser.parse_args()


def extract_python_related_vulnerabilities(xml_file_path):
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    for item in root.findall('.//{http://cve.mitre.org/cve/downloads/1.0}item'):
        cve_id = item.get('name')
        status = item.find('{http://cve.mitre.org/cve/downloads/1.0}status').text
        desc = item.find('{http://cve.mitre.org/cve/downloads/1.0}desc').text

        # Check if the vulnerability is Python-related
        python_related = "python" in desc.lower()

        if python_related:
            # Extract relevant information
            score = item.find('{http://cve.mitre.org/cve/downloads/1.0}score')
            score = score.text if score is not None else "N/A"

            date_element = item.find('{http://cve.mitre.org/cve/downloads/1.0}phase[@date]')
            date_published = date_element.get('date') if date_element is not None else "N/A"

            if date_published != "N/A":
                date_published = datetime.strptime(date_published, "%Y%m%d").strftime("%Y-%m-%d")

            cwe = item.find('{http://cve.mitre.org/cve/downloads/1.0}cwe')
            cwe = cwe.text if cwe is not None else "N/A"

            # Write to CSV
            csv_writer.writerow([desc, cve_id, score, date_published, cwe])

def process_directory(directory_path):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.xml'):
                file_path = os.path.join(root, file)
                extract_python_related_vulnerabilities(file_path)

if __name__ == "__main__":

    list_path = "cvemitrelist"

    if not args.nodownload:
        repo_url = "https://cve.mitre.org/data/downloads/index.html"
        print(f'Scrapping {repo_url} ...')
        response = requests.get(repo_url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find the 'td'
        latest_label_td = soup.find_all('td', {'class': "borderbottomcellboarder"})
        if latest_label_td:
            for latest_label in latest_label_td:
                next_a_tag = latest_label_td.find("a")
                if next_a_tag and next_a_tag.has_attr('href'):
                    href_value = next_a_tag['href']
                    # Check if the href attribute ends with '.gz'
                    if href_value.endswith('.gz'):
                        print(f"Found CVE.mitre.org List (gz) URL: {zip_url}.\nDownloading...")
                        # Download the ZIP file
                        zip_response = requests.get(zip_url)
                        zip_response.raise_for_status()

                        # Extract the ZIP file to list_path
                        os.makedirs(list_path, exist_ok=True)

                        with zipfile.ZipFile(io.BytesIO(zip_response.content)) as zip_ref:
                            zip_ref.extractall(list_path)
                            print(f'List downloaded to {list_path}')
                        
                        # Iterate over all files in the directory
                        for filename in os.listdir(list_path):
                            # Check if the file is a ZIP file by its extension
                            if filename.endswith(".xml.gz"):
                                # Construct the full path to the ZIP file
                                zip_file_path = os.path.join(list_path, filename)
                                
                                with gzip.open(zip_file_path, 'rb') as gz_file:
                                    with open(list_path, 'wb') as output_file:
                                        # Copy the contents of the .gz file to the output file
                                        shutil.copyfileobj(gz_file, output_file)
                                
                                
                                print(f"Extracted {gz_file_path} to {output_file_path}")
                else:
                    exit("Gz link not found.")
        else:
            exit("Latest release link not found.")

    else:
        print('Download flag not set. Skipping download and extraction.')

                

    print(f'Processing CVE.mitre.org list from: {list_path}')
    process_directory(list_path)
    print(f'Number of Python related entries found: {countPythonRelated}')
