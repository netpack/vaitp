import os, json, csv, re, requests, zipfile, io, argparse, importlib.util, sys, time
from datetime import datetime
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

print(f'Starting VAITP cve.org Web Scraper!')


# Set Chrome options for headless mode (optional)
chrome_options = Options()
chrome_options.add_argument("--headless")  # Enable headless mode
chrome_options.add_argument("--no-sandbox")  # Bypass OS security model
chrome_options.add_argument("--disable-dev-shm-usage")  # Overcome limited resource problems

# Initialize the Chrome driver
try:
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
except Exception as e:
    print(f"Error initializing Chrome WebDriver: {e}")

wait = WebDriverWait(driver, 30)  # wait for a maximum of 30 seconds

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


def process_json_file(file_path):
    global countPythonRelated

    with open(file_path, 'r') as json_file:
        data = json.load(json_file)
        
        # Check if the vulnerability is Python-related
        cna = data.get("containers", {}).get("cna", {})
        descriptions = cna.get("descriptions", [])
        
        python_related = any("python" in desc.get("value", "").lower() for desc in descriptions)
        
        if python_related:
            countPythonRelated = countPythonRelated + 1
            cve_id = data["cveMetadata"]["cveId"]
            summary = re.sub('<[^<]+?>', '', descriptions[0]["value"]).replace('\n', ' ').replace('\r', ' ') if descriptions else "N/A"
            score = cna.get("metrics", [{}])[0].get("cvssV3_1", {}).get("baseScore", "N/A")
            
            # Try different date formats
            date_formats = ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"]
            publish_date = "N/A"
            for date_format in date_formats:
                try:
                    date_string = data["cveMetadata"].get("datePublished", "N/A")
                    publish_date = datetime.strptime(date_string, date_format).strftime("%Y-%m-%d")
                    break  # If successful, exit the loop
                except ValueError:
                    pass  # Try the next format

            problem_types = cna.get("problemTypes", {})
            if isinstance(problem_types, dict):
                cwe_id = problem_types.get("descriptions", [{}])[0].get("description", {}).get("value", "N/A")
            else:
                cwe_id = "N/A"
            
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
                

def process_directory(directory_path):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.json') and file != "deltaLog.json":
                #print(f"Processing {file}")
                file_path = os.path.join(root, file)
                process_json_file(file_path)


if __name__ == "__main__":

    list_path = "cvelistV5-main"

    # dont download and extract if --nodownload flag is set
    if not args.nodownload:

        # Scrape the latest release link from the main repository page
        repo_url = 'https://github.com/CVEProject/cvelistV5/'
        print(f'Scrapping {repo_url} ...')
        response = requests.get(repo_url, headers=headers)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find the 'span' with specific attributes indicating the "Latest" release
        latest_label_span = soup.find('span', {'title': "Label: Latest", 'data-view-component': "true", 'class': "Label Label--success flex-shrink-0"})

        # Find the parent 'a' tag of this 'span', which should contain the href to the latest release
        if latest_label_span:
            parent_a_tag = latest_label_span.find_parent('a', href=True)
        else:
            parent_a_tag = None

        # Extract the href attribute if the 'a' tag is found
        latest_release_link = parent_a_tag['href'] if parent_a_tag else "Link to the latest release not found"

        # Construct the full URL
        release_link = f"https://github.com{latest_release_link}" if latest_release_link else exit("Latest release link not found")
        

        if release_link:
            print(f"Found CVE.org Latest Release URL: {release_link}\nScraping page with Selenium JS engine...")

            # we need js..
            # Open the webpage
            driver.get(release_link)

            # Wait for the dynamic content to load
            try:
                first_zip_link_element = wait.until(
                    EC.presence_of_element_located((By.XPATH, '//a[contains(@href, ".zip")]'))
                )


                # Get the href attribute
                zip_url = first_zip_link_element.get_attribute('href') if first_zip_link_element else "Zip link not found"

                #print(zip_url)

                # Clean up by closing the browser
                driver.quit()

                #input("ok?")


                if zip_url:

                    print(f"Found CVE.org Source code (zip) URL: {zip_url}.\nDownloading...")
                    
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
                        if filename.endswith(".zip"):
                            # Construct the full path to the ZIP file
                            zip_file_path = os.path.join(list_path, filename)
                            
                            # Open and extract the ZIP file
                            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                                # Extract all contents to the same directory as the ZIP file
                                zip_ref.extractall(list_path)
                                print(f'Extracted {filename} to {list_path}')
                        else:
                            print("Zip link not found.")

            except TimeoutException:
                print(EC)
                print("The element could not be found within the given time.")


                
            else:
                print("Latest release link not found.")


    else:
        print('Download flag not set. Skipping download and extraction.')



    print(f'Processing CVE.org list from: {list_path}')
    process_directory(list_path)
    print(f'Number of Python related entries found: {countPythonRelated}')

