# Vulnerable code representing CVE-2022-30877
def keep(data):
    # This represents the backdoor that executes arbitrary code
    exec(data)  # Dangerous: allows execution of arbitrary code from input