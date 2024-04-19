import ast,sqlite3

# function to connect to the database
def connect_db():
    # connect to database
    conn = sqlite3.connect('/run/media/b7/26901a06-f703-4da4-8ee4-6a81bcd341f6/CVEfixes.db')
    c = conn.cursor()
    return c, conn

def get_code_changes(cve, c):

    # get hash value from fixes table that matches the input CVE string
    c.execute("SELECT hash FROM fixes WHERE cve_id=?", (cve,))
    hash_value = c.fetchone()

    #check if there is a hash value for the input CVE string
    if hash_value is None:
        print(f'No hash value found for CVE {cve}.')
        return
    else:
        hash_value = hash_value[0]

    # print the hash value
    print(f'Hash value for CVE {cve} is {hash_value}.')

    # retrieve code changes from file_change table using the hash value
    c.execute("SELECT diff_parsed, code_before, code_after FROM file_change WHERE hash=?", (hash_value,))
    row = c.fetchone()
    if row is None:
        print("No code found for CVE {cve}.")
    else:
        diff_parsed, code_before, code_after = row

        # save code_before and code_after to files
        with open(f'codescrapper/code_before/{cve}_{hash_value}_fullcode.txt', 'w') as f:
            f.write(code_before)
        with open(f'codescrapper/code_after/{cve}_{hash_value}_fullcode.txt', 'w') as f:
            f.write(code_after)
        
        # parse the diff_parsed string into a dictionary
        diff_parsed = ast.literal_eval(diff_parsed)

        # get the lines added and deleted
        lines_added = [line[1] for line in diff_parsed['added']]
        lines_deleted = [line[1] for line in diff_parsed['deleted']]

        # save lines_added and lines_deleted to files  
        with open(f'codescrapper/code_before/{cve}_{hash_value}.txt', 'w') as f:
            f.write('\n'.join(lines_deleted))
            # print message to indicate that the code before lines have been saved to file
            print(f'Code before lines for CVE {cve} have been saved to file.')
        with open(f'codescrapper/code_after/{cve}_{hash_value}.txt', 'w') as f:
            f.write('\n'.join(lines_added))
            # print message to indicate that the code after lines have been saved to file
            print(f'Code after lines for CVE {cve} have been saved to file.')

      

if __name__ == "__main__":
    print('Welcome to VAITP code scrapper!')

    # open the database
    c, conn = connect_db()

    # loop each line in the csv file containing each CVE
    with open('cves.csv', 'r') as f:
       for line in f:
           cve = line.strip()
           # print the cve
           print(f'Processing {cve} ')
           get_code_changes(cve, c)

    # close the database
    conn.close()
    print('Database closed! Thank you for using VAITP code scrapper!')