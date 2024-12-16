#import sqlite3, re, requests, time
import mysql.connector, os, requests, time, random, re, importlib, sys
from bs4 import BeautifulSoup

def load_external_module(module_path, module_name):
    """
    Dynamically load a module from the given path.
    """
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}

vaitp_email = load_external_module("/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/py/scrappers/send_mail.py","vaitp_email")


time.sleep(1) #Ensures polite use

# Check if required environment variables are set
required_vars = ['MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_HOST', 'MYSQL_DATABASE', 'SMTP_PASSWORD']
missing_vars = [var for var in required_vars if os.getenv(var) is None]

if missing_vars:
    exit(f"Error: The following environment variables are not set: {', '.join(missing_vars)}")

def execute_query(query, params=None):
    """
    Execute a SQL query

    Parameters:
    - query: str, the SQL query to execute.
    - results: list, the results of the executed query.
    """
    cnx = mysql.connector.connect(
        user=os.getenv('MYSQL_USER'),
        password=os.getenv('MYSQL_PASSWORD'),
        host=os.getenv('MYSQL_HOST'),
        database=os.getenv('MYSQL_DATABASE')
    )

    try:
        # Create a cursor object
        cursor = cnx.cursor()
        # Execute query
        cursor.execute(query, params)
        # Fetch all rows from the last executed statement
        results = cursor.fetchall()
        # Commit the transaction
        cnx.commit()
        return results
    except mysql.connector.Error as err:
        print("Something went wrong: {}".format(err))
    finally:
        #try to close
        try:
            # Close the cursor and connection (even if there is an error)
            cursor.close
            cnx.close
        except:
            pass


def insert_vulnerability(summary, cve_id, cvss_score, cve_publish_date_value, cwe_id):
    """
    Insert a vulnerability into the python_vulnerabilities table.

    Parameters:
    - summary: str, the summary of the vulnerability.
    - cve_id: str, the CVE ID of the vulnerability.
    - cvss_score: float, the CVSS score of the vulnerability.
    - cve_publish_date_value: str, the publication date of the CVE.
    - cwe_id: int, the CWE ID related to the vulnerability.
    """
    cnx = mysql.connector.connect(
        user=os.getenv('MYSQL_USER'),
        password=os.getenv('MYSQL_PASSWORD'),
        host=os.getenv('MYSQL_HOST'),
        database=os.getenv('MYSQL_DATABASE')
    )

    cve_url = f"https://www.cvedetails.com/cve/{cve_id}/"
    
    # If the cvss score, publish date, or cwe id is N/A try to scrape it from cvedetails

    if cvss_score == "N/A" or cve_publish_date_value == "N/A" or cwe_id == "N/A":
        newResponse = requests.get(cve_url, headers=headers)
        newSoup = BeautifulSoup(newResponse.text, "html.parser")
    
    try:
        cwe_pattern = r'CWE-(\d+)'
        cwe_num = re.search(cwe_pattern, cwe_id).group(1)
    except AttributeError:
        print("Detected empty CWE. Trying to scrape from cvedetails.com with this CVE ID...")
        # Locate the elements containing CWE information
        cwe_header = newSoup.find('h2', string=lambda text: text and text.startswith('CWE ids for '))
        if cwe_header:
                cwe_elements = cwe_header.find_next('li').find('a')
                cwe_num = cwe_elements.text.strip()
                print(f'Found CWE {cwe_num} for {cve_id}!')
        else:
            cwe_num = "N/A"
            
    cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}/" if cwe_num != "N/A" else "N/A"


    if cvss_score == "N/A":
        print("Detected empty CVSS Score. Trying to scrape from cvedetails.com with this CVE ID...")
        # Finding the CVSS score based on the provided structure
        cvss_score_div = newSoup.find('div', class_='cvssbox')

        # Extracting the numerical value of the CVSS score
        if cvss_score_div:
            cvss_score = cvss_score_div.text.strip()
            print(f"CVSS Score for {cve_id}: {cvss_score}")
        else:
            print("CVSS Score not found.")
    

    if cve_publish_date_value == "N/A":
        print("Detected empty publish date. Trying to scrape from cvedetails.com with this CVE ID...")
        publish_date = newSoup.find('span', string=lambda text: text and text.startswith('Published'))
        if publish_date:
            cve_publish_date = publish_date.find_parent('div').text.strip()
            cve_date_pattern = r'\b\d{4}-\d{2}-\d{2}\b'
            cve_publish_date_value = re.search(cve_date_pattern, cve_publish_date).group(0)


    try:
        # Create a cursor object
        cursor = cnx.cursor()
        query = """
        INSERT INTO python_vulnerabilities (ID, VulnerabilityLongDescription, CVE, CVELink, Score, Publishdate, CWE, CWELink)
        VALUES (NULL,%s, %s, %s, %s, %s, %s, %s);
        """
        cursor.execute(query, (summary,cve_id,cve_url,cvss_score,cve_publish_date_value,cwe_num,cwe_url))
        cnx.commit()
        print(f"VAITP dataset updated with {cve_id}. Sending email to admin...")
       
        msg = f"<h2>{cve_id}</h2><br>{summary}<br>Disclosure date: {cve_publish_date_value}<br>Score: {cvss_score}<br>CWE: {cwe_num}<br>VAITP Link: https://netpack.pt/vaitp/dataset/?vcve={cve_id}<br>"
        sender_email = "vaitp@netpack.pt"
        sender_password=os.getenv('SMTP_PASSWORD')
        # # List of recipient email addresses
        recipient_emails = [
            "info@netpack.pt"
        ]
        vaitp_email.send_html_email(sender_email, sender_password, recipient_emails, msg)

    except Exception as e:
        print(f"Error updating VAITP dataset: {e}")
    finally:
        try:
            cursor.close
            cnx.close
        except:
            pass

