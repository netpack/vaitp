import sqlite3, ast, pyautogui, time, pyperclip

autopaste = False

totalProcessedCVES=0
totalFromHash=0
totalFromDiff=0
totalFromFixes=0
totalFromMethodChange=0
totalFromCommitMsg=0

# function to connect to the database
def connect_db():
    # connect to database
    conn = sqlite3.connect('CVEfixes.db')
    c = conn.cursor()
    return c, conn


def is_empty_line(line):
    return not line.strip()


def clean_lines(input_list):
    result_list = []
    for input_string in input_list:
         if not is_empty_line(input_string):
            result_list.append(input_string)

    return result_list


def save2files(cve, hash_value, lines_deleted, lines_added):
    # save lines_added and lines_deleted to files  
    with open(f'codescrapper/code_before/{cve}_{hash_value}.txt', 'w') as f:
        f.write('\n'.join(lines_deleted))
        # print message to indicate that the code before lines have been saved to file
        print(f'Code before lines for CVE {cve} have been saved to file.')
    with open(f'codescrapper/code_after/{cve}_{hash_value}.txt', 'w') as f:
        f.write('\n'.join(lines_added))
        # print message to indicate that the code after lines have been saved to file
        print(f'Code after lines for CVE {cve} have been saved to file.')


def autoPaste(cve, lines_added, lines_deleted):
    global autopaste
    if autopaste:
        pyautogui.click(452,12) #firefox
        pyautogui.hotkey('ctrl','f') #find
        pyautogui.write(cve)
        time.sleep(1)
        pyautogui.press(['esc'])
        time.sleep(1)
        pyautogui.press(['right'], 13, 0.2)
        time.sleep(1)
        pyautogui.press(['enter'])
        time.sleep(1)
        pyautogui.hotkey('ctrl','a')
        time.sleep(1)
    
        # Convert the list of lines to a single string with line breaks
        text_to_paste = '\n'.join(lines_added)
        # Copy the text to the clipboard
        pyperclip.copy(text_to_paste)
        time.sleep(1)
        pyautogui.hotkey('ctrl', 'v')
    
        time.sleep(1)
        pyautogui.press(['tab'])
        time.sleep(1)
        pyautogui.press(['enter'])
        time.sleep(1)
        pyautogui.hotkey('ctrl','a')
        time.sleep(1)
    
        # Convert the list of lines to a single string with line breaks
        text_to_paste = '\n'.join(lines_deleted)
        # Copy the text to the clipboard
        pyperclip.copy(text_to_paste)
        time.sleep(1)
        pyautogui.hotkey('ctrl', 'v')
    
        time.sleep(1)
        pyautogui.press(['enter'])


def get_code_changes(cve, c):

    global totalFromHash, totalFromDiff, totalFromFixes, totalFromMethodChange, totalFromCommitMsg, autopaste


    # get hash value from fixes table that matches the input CVE string
    print('\t[1] Quering hashes from diffs :: [SELECT hash FROM fixes WHERE cve_id=?] ...')
    c.execute("SELECT hash FROM fixes WHERE cve_id=?", (cve,))
    hash_value = c.fetchone()

    #check if there is a hash value for the input CVE string
    if hash_value is None:
        print(f'\t\t-No hash value found for CVE {cve} in cves table.')
    else:
        hash_value = hash_value[0]
        print(f'Found hash for {cve}: {hash_value}')

        # retrieve code changes from file_change table using the hash value
        c.execute("SELECT diff_parsed FROM file_change WHERE hash=?", (hash_value,))

        val = c.fetchone()
        if val is None:
            print(f'No diff_parsed value found for CVE {cve} in file_change table although it has a hash...')
        else:
            # process each returned row
            n=0
            for row in c.fetchall():
                for item in row:
                    totalFromHash=totalFromHash+1
                    print(f'Found a hash that references {cve} in cves table:\n{item}')

                    # parse the diff_parsed string into a dictionary
                    diff_parsed = ast.literal_eval(item)

                    # get the lines added and deleted
                    lines_added = clean_lines([line[1] for line in diff_parsed['added']])
                    lines_deleted = clean_lines([line[1] for line in diff_parsed['deleted']])
                    print(f"Added lines: {lines_added}")
                    print(f'Deleted lines: {lines_deleted}')
                
                    save2files(cve, hash_value, lines_deleted, lines_added)
                    if n==0:
                        autoPaste(cve, lines_added, lines_deleted)
                    n = 1
                    print("\n" + "=" * 20 + "\n")

    #Check if any there is any diff that mentions this CVE
    print('\t[2] Quering parsed diffs from file changes :: [SELECT diff_parsed FROM file_change WHERE diff_parsed LIKE ?] ...')        
    c.execute("SELECT diff_parsed FROM file_change WHERE diff_parsed LIKE ?", ('%' + cve + '%',))

    val = c.fetchone()
    if val is None:
        print('\t\t-No CVE like value found in diff_parsed from file_change table')
    else:
        n=0
        for row in c.fetchall():
            for item in row:
                totalFromDiff=totalFromDiff+1
                print(f'Found a reference to {cve} in diff_parsed:\n{item}')
                diff_parsed = ast.literal_eval(item)
                # get the lines added and deleted
                lines_added = clean_lines([line[1] for line in diff_parsed['added']])
                lines_deleted = clean_lines([line[1] for line in diff_parsed['deleted']])
                print(f"Added lines: {lines_added}")
                print(f'Deleted lines: {lines_deleted}')
                save2files(cve, hash_value, lines_deleted, lines_added)
                if n==0 and autopaste:
                    autoPaste(cve, lines_added, lines_deleted)
                n = 1
    
    #Check if there is a hask in the fixes table for this vulnerability
    print('\t[3] Quering hashes from fixes :: [SELECT hash FROM fixes WHERE cve_id=?] ...') 
    c.execute("SELECT hash FROM fixes WHERE cve_id=?", (cve,))

    val = c.fetchone()
    if val is None:
        print(f'\t\t-No hash value found for CVE {cve} in fixes table')
    else:
        n=0
        for row in c.fetchall():
            for item in row:
                totalFromFixes = totalFromFixes+1
                print(f'Found a hash that references {cve} in fixes:\n{item}')
                

    #Check if any there is any method_change that mentions this CVE        
    print('\t[4] Quering code from changed methods :: [SELECT code FROM method_change WHERE code LIKE ?] ...') 
    c.execute("SELECT code FROM method_change WHERE code LIKE ?", ('%' + cve + '%',))

    val = c.fetchone()
    if val is None:
        print('\t\t-No CVE like value found in code from method_change table')
    else:
        n=0
        for row in c.fetchall():
            for item in row:
                totalFromMethodChange=totalFromMethodChange+1
                print(f'Found a reference to {cve} in method_change:\n{item}')
                diff_parsed = ast.literal_eval(item)
                # get the lines added and deleted
                lines_added = clean_lines([line[1] for line in diff_parsed['added']])
                lines_deleted = clean_lines([line[1] for line in diff_parsed['deleted']])
                print(f"Added lines: {lines_added}")
                print(f'Deleted lines: {lines_deleted}')
                save2files(cve, hash_value, lines_deleted, lines_added)
                if n==0 and autopaste:
                    autoPaste(cve, lines_added, lines_deleted)
                n = 1
        
    #Check if any there is any general message in the commit that mentions this CVE  
    print('\t[5] Quering hashes from commit messages :: [SELECT hash FROM commits WHERE msg LIKE ?] ...')       
    c.execute("SELECT hash FROM commits WHERE msg LIKE ?", ('%' + cve + '%',))

    val = c.fetchone()
    if val is None:
        print('\t\t-No hash for CVE like value found in commits.msg [cvefixes]')
    else:
        n=0
        for row in c.fetchall():
            for item in row:
                totalFromCommitMsg=totalFromCommitMsg+1
                print(f':::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\
                          Found a reference to {cve} in method_change:\n{item}')
                


if __name__ == "__main__":
    print('Welcome to VAITP code scrapper [autoPaste]!')

    # open the database
    c, conn = connect_db()

    # loop each line in the csv file containing each CVE
    with open('cves.csv', 'r') as f:
       for line in f:
           cve = line.strip()
           totalProcessedCVES=totalProcessedCVES+1
           # print the cve
           print(f'\n :::::::::::::::::::::  Processing {cve}  [{totalProcessedCVES}] ::::::::::::::::::::: ')
           get_code_changes(cve, c)


    print(f'Total processed CVES: {totalProcessedCVES}')
    print(f'Total entries from Hash: {totalFromHash}')
    print(f'Total entries from Diff: {totalFromDiff}')
    print(f'Total entries from Fixes: {totalFromFixes}')
    print(f'Total entries from Method change: {totalFromMethodChange}')
    print(f'Total entries from Commit Msgs: {totalFromCommitMsg}')
    # close the database
    conn.close()
    print('Database closed! Thank you for using VAITP code scrapper!')
    