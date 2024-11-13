import sqlite3, re, requests, time
from bs4 import BeautifulSoup

db_path = '/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/vaitp.db'
    
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}

def execute_query(query):
    """
    Execute a SQL query

    Parameters:
    - db_path: str, the path to the SQLite database file.
    - query: str, the SQL query to execute.

    - results: list, the results of the executed query.
    """
    global db_path
    # Connect to the SQLite database
    conn = sqlite3.connect(db_path)
    
    try:
        # Create a cursor object using the cursor() method
        cursor = conn.cursor()
        
        # Execute the SQL query
        cursor.execute(query)
        
        # Fetch all rows from the last executed statement
        results = cursor.fetchall()
        
        return results
    finally:
        # Ensure the database connection is closed even if an error occurs
        conn.close()


def insert_vulnerability(summary, cve_id, cvss_score, cve_publish_date_value, cwe_id):
    """
    Insert a vulnerability into the python_vulnerabilities table.

    Parameters:
    - db_path: str, the path to the SQLite database file.
    - summary: str, the summary of the vulnerability.
    - cve_id: str, the CVE ID of the vulnerability.
    - cvss_score: float, the CVSS score of the vulnerability.
    - cve_publish_date_value: str, the publication date of the CVE.
    - cwe_id: int, the CWE ID related to the vulnerability.
    """

    global db_path

    if cvss_score == "N/A" or cve_publish_date_value == "N/A" or cwe_id == "N/A":
        newResponse = requests.get(f"https://www.cvedetails.com/cve/{cve_id}", headers=headers)
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
            

    cve_url = f"https://www.cvedetails.com/cve/{cve_id}/"
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


    query = """
    INSERT INTO python_vulnerabilities (ID, VulnerabilityLongDescription, CVE, CVELink, Score, Publishdate, CWE, CWELink)
    VALUES (NULL,?, ?, ?, ?, ?, ?, ?);
    """
    
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(query, (summary, cve_id, cve_url, cvss_score, cve_publish_date_value, cwe_num, cwe_url))
        conn.commit()
    finally:
        conn.close()

