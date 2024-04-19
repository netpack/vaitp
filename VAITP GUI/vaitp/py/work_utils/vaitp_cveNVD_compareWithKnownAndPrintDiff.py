import csv, time, pyautogui, pyperclip, random, keyboard, re

def check_and_print_missing_cves():
    # Define the file paths
    webscraper_file_path = 'VAITP_CVENVD_PythonRelatedVulnerabilities.csv'
    known_cves_file_path = 'VAITP_KnownCVES.csv'
    ignored_cves_file_path = 'VAITP_IgnoreCVES.csv'

    # Read the known CVEs into a set for faster lookup
    known_cves_set = set()
    with open(known_cves_file_path, 'r', newline='') as known_cves_file:
        known_cves_reader = csv.reader(known_cves_file)
        for row in known_cves_reader:
            known_cves_set.add(row[0]) 

    # Read the ignored CVEs
    ignored_cves_set = set()
    with open(ignored_cves_file_path, 'r', newline='') as ignored_cves_file:
        ignored_cves_reader = csv.reader(ignored_cves_file)
        for row in ignored_cves_reader:
            ignored_cves_set.add(row[0]) 


    # Check each row in the webscraper file
    with open(webscraper_file_path, 'r', newline='') as webscraper_file:
        webscraper_reader = csv.reader(webscraper_file, delimiter=',')
        for row in webscraper_reader:
            # Check if the value in the second column is not present in the known CVEs
            if row[1] not in known_cves_set and row[1] not in ignored_cves_set:
                # Print all columns of that row
                print(row[1])
                pyautogui.press("down")
                time.sleep(1)
                pyautogui.press("enter")
                pyperclip.copy(row[0])
                time.sleep(1)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(1)
                pyautogui.press("tab")
                time.sleep(1)
                pyautogui.press("enter")
                pyperclip.copy(row[1])
                time.sleep(1)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(1)
                pyautogui.press("tab")
                time.sleep(1)
                pyautogui.press("right")
                time.sleep(1)
                pyautogui.press("enter")
                pyperclip.copy(row[2])
                time.sleep(1)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(1)
                pyautogui.press("tab")
                time.sleep(1)
                pyautogui.press("enter")
                pyperclip.copy(row[3])
                time.sleep(1)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(1)
                pyautogui.press("tab")
                time.sleep(1)
                pyautogui.press("enter")
                pyperclip.copy(row[4])
                time.sleep(1)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(1)
                pyautogui.press("tab")

                time.sleep(1)
                pyautogui.press("left", 6, 0.5)
                


# Call the function to check and print missing CVEs
pyautogui.click(1135,16) #FF
time.sleep(1)
check_and_print_missing_cves()
