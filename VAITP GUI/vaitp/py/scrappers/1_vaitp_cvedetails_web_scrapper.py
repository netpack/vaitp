import requests, re, time, sqlite3, importlib.util, sys
from bs4 import BeautifulSoup

verbose = True

print('Starting cvedetails.com Web Scapper!') 


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


page_num = 1
url = f"https://www.cvedetails.com/vulnerability-search-fulltext?f=1&page={page_num}&q=python"


def get_page(aUrl):

    global page_num
    global headers
    
    # Print the scraped page URL if verbose
    verbose and print(f'Scraping URL: {aUrl}')

    # Send an HTTP GET request to the URL
    response = requests.get(aUrl, headers=headers)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Parse the HTML content of the page using BeautifulSoup
        soup = BeautifulSoup(response.text, "html.parser")
        #verbose and print(f'Processing HTML response: {soup}')
        
        # Locate the elements containing CVE information
        cve_elements = soup.find_all("div", attrs={"data-tsvfield": "cveinfo"})

        # Check if cve_elements is empty
        if not cve_elements:
            print("No CVE information found. Please check the HTML structure or the class names.")
            sys.exit(1)  # Exit the script with a non-zero status to indicate an error

                
        # Loop through the elements and extract CVE ID and Summary
        for element in cve_elements:
            
            # Extract CVE ID from the <h3> tag
            cve_id = element.find("h3", attrs={"data-tsvfield": "cveId"}).a.text.strip()

            verbose and print(f'Scraping found a new CVE: {cve_id}')

            query = f"SELECT id FROM python_vulnerabilities WHERE cve LIKE '{cve_id}';"
            results = vaitp_db.execute_query(query)

            if results:
                print(f'Skipping known CVE: {cve_id}')
            else:

                print(f'Found an UNKOWN CVE: {cve_id}')
                
                # Extract Summary from the <div> with class "cvesummarylong"
                summary = element.find("div", class_="cvesummarylong", attrs={"data-tsvfield": "summary"}).text.strip()

                newResponse = requests.get(f"https://www.cvedetails.com/cve/{cve_id}", headers=headers)
                newSoup = BeautifulSoup(newResponse.text, "html.parser")
                # Locate the elements containing CWE information
                cwe_header = newSoup.find('h2', string=lambda text: text and text.startswith('CWE ids for '))


                # Finding the CVSS score based on the provided structure
                cvss_score_div = newSoup.find('div', class_='cvssbox')

                # Extracting the numerical value of the CVSS score
                if cvss_score_div:
                    cvss_score = cvss_score_div.text.strip()
                    print(f"CVSS Score for {cve_id}: {cvss_score}")
                else:
                    cvss_score = "N/A"
                    print("CVSS Score not found.")

                publish_date = newSoup.find('span', string=lambda text: text and text.startswith('Published'))

                if publish_date:
                    cve_publish_date = publish_date.find_parent('div').text.strip()
                    cve_date_pattern = r'\b\d{4}-\d{2}-\d{2}\b'
                    cve_publish_date_value = re.search(cve_date_pattern, cve_publish_date).group(0)

                else:
                    cve_publish_date_value = "N/A"
                    

                if cwe_header:

                    cwe_elements = cwe_header.find_next('li').find('a')
                    cwe_id = cwe_elements.text.strip()

                else:
                    cwe_id = "N/A"
                
                # It's a mi! Mário!
                #verbose and print(f"\"{summary}\"~~~\"{cve_id}\"~~~\"https://www.cvedetails.com/cve/{cve_id}\"~~~{cvss_score}~~~{cve_publish_date_value}~~~{cwe_id}~~~https://cwe.mitre.org/data/definitions/{cwe_num}")
                
                vaitp_db.insert_vulnerability(summary, cve_id, cvss_score, cve_publish_date_value, cwe_id)
                print(f'New vulnerability added to the database: {cve_id}')
                #input('Continue?')


        # Check if there is a 'Next Page' button
        next_button = soup.find_all("button", attrs={"title": "Next page"})
        if next_button:
            print('Next button found! Getting next page...')
            page_num = page_num + 1
            newUrl = f"https://www.cvedetails.com/vulnerability-search-fulltext?f=1&page={page_num}&q=python"
            print(f'Processing {newUrl}')
            get_page(newUrl)
        else:
            print('No Next button found! All pages were processed!')



if __name__ == "__main__":
     
    get_page(url)
