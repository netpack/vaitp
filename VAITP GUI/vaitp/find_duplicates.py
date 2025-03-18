import csv
import sys

def process_csv(input_file, output_file):
    try:
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(input_file, 'r', encoding=encoding) as infile, \
                     open(output_file, 'w', encoding=encoding, newline='') as outfile:
                    
                    reader = csv.reader(infile, delimiter=';', quotechar='"')
                    writer = csv.writer(outfile, delimiter=';', quotechar='"', quoting=csv.QUOTE_ALL)
                    
                    # Write header
                    header = next(reader)
                    writer.writerow(header)
                    
                    # Process rows
                    removed_count = 0
                    total_count = 0
                    
                    for row in reader:
                        total_count += 1
                        if len(row) >= 21:  # Ensure we have enough columns
                            patched_code = row[19]  # PatchedCodeSample
                            vulnerable_code = row[20]  # VulnerableCodeSample
                            
                            if patched_code != vulnerable_code:
                                writer.writerow(row)
                            else:
                                removed_count += 1
                    
                    print(f"Successfully processed the file using {encoding} encoding")
                    print(f"Total entries processed: {total_count}")
                    print(f"Removed {removed_count} entries where patched code was identical to vulnerable code")
                    print(f"Remaining entries: {total_count - removed_count}")
                    return True
            except UnicodeDecodeError:
                continue
        
        print("Failed to process the file with any of the attempted encodings")
        return False
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return False

if __name__ == '__main__':
    input_file = 'vaitp_dataset/python_vulnerabilities.csv'
    output_file = 'vaitp_dataset/python_vulnerabilities_cleaned.csv'
    process_csv(input_file, output_file) 