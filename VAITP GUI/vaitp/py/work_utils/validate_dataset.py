import os
import mysql.connector
import google, google.generativeai as genai
import time
import random
import sys

# Configure Gemini API
genai.configure(api_key=os.getenv('GEMINI_API_KEY')) 
model = genai.GenerativeModel("gemini-2.0-flash-exp")

# Check if required environment variables are set
required_vars = ['MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_HOST', 'MYSQL_DATABASE', 'GEMINI_API_KEY']
missing_vars = [var for var in required_vars if os.getenv(var) is None]

# Database Configuration
db_config = {
    "host": os.getenv('MYSQL_HOST'),  
    "user": os.getenv('MYSQL_USER'),  
    "password": os.getenv('MYSQL_PASSWORD'), 
    "database": os.getenv('MYSQL_DATABASE') 
}

# Directories
injectable_dir = "/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/vaitp_dataset/train/injectable"
noninjectable_dir = "/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/vaitp_dataset/train/noninjectable"

#Time between requests
min_delay = 20
max_delay = 40
thinking_msg = "Thinking..."

# Flag to check if we exceeded the Gemini API Quota
gemini_quota_exceeded = False

def remove_first_and_last_line_if_match(text, first_match_string="```python", last_match_string="```"):
    # Split the text into lines
    lines = text.splitlines()

    # Check if the first line matches the specified first match string
    if lines and lines[0] == first_match_string:
        lines = lines[1:]  # Remove the first line

    # Check if the last line matches the specified last match string
    if lines and lines[-1] == last_match_string:
        lines = lines[:-1]  # Remove the last line

    # Join the remaining lines back into a single string
    return "\n".join(lines)

def connect_to_db():
    try:
        conn = mysql.connector.connect(**db_config)
        if conn.is_connected():
            print("Connected to MySQL database")
            return conn
        else:
            print("Failed to connect to MySQL database")
            return None
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

def get_vulnerabilities(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT ID, CVE, VulnerabilityLongDescription FROM python_vulnerabilities where ID > 1025 and isPython = 1 and ignored = 0")
    vulnerabilities = cursor.fetchall()
    return vulnerabilities

def validate_file(filepath, cve, description):
  global gemini_quota_exceeded

  try:
    if gemini_quota_exceeded:
        return False # Stop immediately if the flag is up

    print(thinking_msg)
    time.sleep(random.randint(min_delay,max_delay)) #Time sleep here

    with open(filepath, 'r') as file:
        file_content = file.read()
    
    # Validate Python code syntax with Gemini
    validate_query = f"Check if the provided code is valid Python code: ```\n{file_content}\n```.\nIf there are errors please provide the corrected code inside ```python ``` tags and say 'Fixed' before the tag. Otherwise, just say 'Valid' and nothing else."
    response = model.generate_content(validate_query)
    response_value = response._result.candidates[0].content.parts[0].text
    
    if "Valid" not in response_value and "Fixed" not in response_value:
      print(f"Gemini failed to check Python code validity for: {filepath}")
    elif "Valid" not in response_value:
        fixed_code = remove_first_and_last_line_if_match(response_value.replace("Fixed\n",""))
        with open(filepath, 'w') as file:
            file.write(fixed_code)
        print(f"Fixed Python syntax errors in: {filepath}")

    # Validate file relevance with Gemini
    relevance_query = f"Is the following Python code related in any way (before or after the vulnerability patch), or is a possible example of the vulnerability or its patch, to the vulnerability with CVE: {cve} and description: '{description}'? Answer with 'Related' or 'Unrelated' only, and nothing else: ```\n{file_content}\n```"
    response = model.generate_content(relevance_query)
    relevance_value = response._result.candidates[0].content.parts[0].text
    
    if "Related" in relevance_value:
      print(f"File is relevant to CVE {cve}: {filepath}")
      return True
    else:
      print(f"File is irrelevant to CVE {cve}: {filepath}")
      os.remove(filepath)
      print(f"Deleted irrelevant file: {filepath}")
      return False


  except google.api_core.exceptions.ResourceExhausted as e:
      if "429 Resource has been exhausted" in str(e):
          exit("Gemini API quota exceeded during validation. Exiting.")
      else:
          print(f"An error occurred during Gemini request: {e}")
          return False
  except Exception as e:
      print(f"Error validating {filepath}: {e}")
      if "429" in e:
         exit("419 in gemini... :-/")
      return False


def process_files(vulnerabilities):
  global gemini_quota_exceeded
  for vuln in vulnerabilities:
    if gemini_quota_exceeded:
      exit("Gemini quota is over...")
    vuln_id, cve, description = vuln

    # Process injectable files
    injectable_files = [f for f in os.listdir(injectable_dir) if os.path.isfile(os.path.join(injectable_dir, f)) and f.startswith(str(vuln_id) + "_")]
    for file in injectable_files:
      filepath = os.path.join(injectable_dir, file)
      if not validate_file(filepath, cve, description):
        pass # do nothing as the validate_file will do what is needed

    # Process non-injectable files
    noninjectable_files = [f for f in os.listdir(noninjectable_dir) if os.path.isfile(os.path.join(noninjectable_dir, f)) and f.startswith(str(vuln_id) + "_")]
    for file in noninjectable_files:
      filepath = os.path.join(noninjectable_dir, file)
      if not validate_file(filepath, cve, description):
        pass # do nothing as the validate_file will do what is needed
              
if __name__ == "__main__":
    print("Starting VAITP dataset validation tool [based on Gemini 2.0 exp LLM]")
    conn = connect_to_db()
    if conn:
        vulnerabilities = get_vulnerabilities(conn)
        process_files(vulnerabilities)
        conn.close()
        if gemini_quota_exceeded:
          print("Gemini Quota was exceeded, exiting...")
          sys.exit(1) # stop the program using sys.exit()
        print("Dataset validation completed.")
    else:
        print("Failed to connect to the database. Cannot validate the dataset.")