import python_libnmap

nmap = python_libnmap.Nmap()

# Vulnerable code: user_input is not validated
user_input = input("Enter a command: ")
nmap.scan(user_input)

# Execute the scan
nmap.scan()

# Print the results
print(nmap.scan_result)