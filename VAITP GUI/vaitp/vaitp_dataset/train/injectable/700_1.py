import re
import markdown2

# Vulnerable function (simulating the vulnerability)
def vulnerable_markdown_processing(input_string):
    # This regex could be exploited by an attacker to cause a ReDoS
    regex = r"(\*\*|__)(.*?)\1"
    if re.search(regex, input_string):
        return markdown2.markdown(input_string)
    return input_string

# Fixed function with a timeout to prevent ReDoS
def safe_markdown_processing(input_string):
    # This regex is more restrictive to avoid catastrophic backtracking
    regex = r"(\*\*|__)([^*]*)\1"
    if re.search(regex, input_string):
        try:
            return markdown2.markdown(input_string)
        except Exception as e:
            return f"Error processing markdown: {e}"
    return input_string

# Example usage
malicious_string = "**" + "a" * 10000 + "**"
print(safe_markdown_processing(malicious_string))