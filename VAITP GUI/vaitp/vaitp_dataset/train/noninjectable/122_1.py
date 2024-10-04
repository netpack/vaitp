# This code is for demonstration purposes only. Do not use it in production.
import openpyxl

# This xlsx file contains an external entity reference to a malicious DTD
xlsx_file = "malicious.xlsx"

# This will trigger the vulnerability and allow the attacker to read local files
wb = openpyxl.load_workbook(xlsx_file)