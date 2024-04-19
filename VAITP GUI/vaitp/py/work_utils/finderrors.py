import csv

def compare_values(csv_file, values_list):
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        
        # Assuming the values in the CSV are in the first column
        for row in reader:
            if row:  # Skip empty rows
                csv_value = row[0]
                #print(f'::{csv_value}')
                
                if csv_value not in values_list:
                    print(f"Value {csv_value} not in the list")

# Example usage
csv_file_path = 'cats.csv'
subcats = ["Input Validation and Data Sanitization","Command Injection","SQL Injection","Insecure Direct Object References (IDOR)","Path Traversal","Insecure Parsing or Deserialization","Weak Password Policies","Insecure Authentication Mechanisms","Session Management Issues","Privilege Escalation","Unencrypted communication","Weak encryption algorithm","Inadequate random number generation","Improper SSL/TLS Certificate Validation","Cryptographic Implementation Error","Inadequate Error Handling","Vulnerable and Outdated Components","Poorly Designed Access Controls","Security Misconfigurations","Cross-Site Scripting (XSS)","Cross-Site Request Forgery (CSRF)","Remote File Inclusion (RFI)","Local File Inclusion (LFI)","Open Redirects","Server-Side Request Forgery (SSRF)","Dynamic Link Library (DLL) Loading Issues","Buffer Overflows","Out-of-Bound Accesses","Use-After-Free Errors","Information Disclosure","Insecure Handling of Sensitive Data","Time-of-Check to Time-of-Use","Data Race Conditions in Threads","Race Condition in File Operations","File Handle Leaks","Socket Handle Leaks","Memory Leaks","Resource Exhaustion","Integer Overflows","Rounding Errors","Floating-Point Precision Issues","Arithmetic Errors"]

compare_values(csv_file_path, subcats)