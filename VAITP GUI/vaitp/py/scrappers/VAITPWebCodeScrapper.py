import csv,random,time,requests
from bs4 import BeautifulSoup

def google_search(query, start=0):
    url = f"https://www.google.com/search?q={query}&start={start}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    print(f'Query :: {url}')

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.text
    else:
        print(f"Failed to retrieve Google search results for {query}. Status code: {response.status_code}")
        return None

def extract_code_samples(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    
    code_samples = []

    # Extract code samples from the search results
    for code_block in soup.find_all('code'):
        code_samples.append(code_block.get_text())

    return code_samples

def scrape_page(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.text
    else:
        print(f"Failed to retrieve page at {url}. Status code: {response.status_code}")
        return None

def main():
    print("Opening csv...")
    # Read CVEs from a CSV file
    with open('cves.csv', newline='') as csvfile:
        cve_reader = csv.reader(csvfile)
        cves = [row[0] for row in cve_reader]

    for cve in cves:
        all_result_links = []

        for start_page in range(0, 10, 10):  # Adjust the range based on the number of pages you want to scrape
            query = f"{cve}"
            print(f'Quering {cve} [::]')
            search_results = google_search(query, start=start_page)

            if search_results:
                # Introduce a random delay between 5 to 10 seconds
                delay = random.uniform(5, 10)
                print(f'Proceding [{delay}]')
                time.sleep(delay)

                # Extract URLs from the current page
                soup = BeautifulSoup(search_results, 'html.parser')
                result_links = [a['href'] for a in soup.find_all('a', href=True) if 'url?q=' in a['href']]
                all_result_links.extend(result_links)

        # Process each link found across all result pages
        for link in all_result_links:

            print(f'Scrapping link: {link}')

            # Extract content from each page
            page_content = scrape_page(link)

            if page_content:
                code_samples = extract_code_samples(page_content)

                if code_samples:
                    print(f"Code samples for {cve} on {link}:\n")
                    for i, code_sample in enumerate(code_samples, 1):
                        print(f"Code Sample {i}:\n{code_sample}\n{'-'*50}\n")
                else:
                    print(f"No code samples found for {cve} on {link}.")
            else:
                print(f"Skipping {cve} on {link} due to failed page retrieval.")

if __name__ == "__main__":
    print('Starting...')
    main()
