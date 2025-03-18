import csv
import math

def split_dataset(input_file, output_file1, output_file2):
    try:
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(input_file, 'r', encoding=encoding) as infile:
                    # First, count total rows
                    reader = csv.reader(infile, delimiter=';', quotechar='"')
                    header = next(reader)  # Skip header when counting
                    total_rows = sum(1 for row in reader)
                    
                    # Calculate split point (half of total rows)
                    split_point = math.ceil(total_rows / 2)
                    
                    # Reset file pointer
                    infile.seek(0)
                    reader = csv.reader(infile, delimiter=';', quotechar='"')
                    header = next(reader)  # Get header again
                    
                    # Open output files
                    with open(output_file1, 'w', encoding=encoding, newline='') as outfile1, \
                         open(output_file2, 'w', encoding=encoding, newline='') as outfile2:
                        
                        writer1 = csv.writer(outfile1, delimiter=';', quotechar='"', quoting=csv.QUOTE_ALL)
                        writer2 = csv.writer(outfile2, delimiter=';', quotechar='"', quoting=csv.QUOTE_ALL)
                        
                        # Write headers to both files
                        writer1.writerow(header)
                        writer2.writerow(header)
                        
                        # Write first half
                        for i, row in enumerate(reader):
                            if i < split_point:
                                writer1.writerow(row)
                            else:
                                writer2.writerow(row)
                    
                    print(f"Successfully split the dataset using {encoding} encoding")
                    print(f"Total entries: {total_rows}")
                    print(f"First file entries: {split_point}")
                    print(f"Second file entries: {total_rows - split_point}")
                    return True
                    
            except UnicodeDecodeError:
                continue
        
        print("Failed to process the file with any of the attempted encodings")
        return False
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return False

if __name__ == '__main__':
    input_file = 'vaitp_dataset/python_vulnerabilities_cleaned.csv'
    output_file1 = 'vaitp_dataset/python_vulnerabilities_part1.csv'
    output_file2 = 'vaitp_dataset/python_vulnerabilities_part2.csv'
    split_dataset(input_file, output_file1, output_file2) 