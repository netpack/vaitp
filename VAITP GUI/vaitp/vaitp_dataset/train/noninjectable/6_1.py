import email.utils

# A crafted argument designed to trigger the recursion error
malicious_input = "A" * 10**6 + "@example.com"

try:
    # This call will trigger the RecursionError
    result = email.utils.parseaddr(malicious_input)
except RecursionError as e:
    print(f"RecursionError: {e}")
