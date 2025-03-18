import email.header
import email.utils

def demonstrate_cve_2025_1795(display_name, email_address, charset='utf-8'):
    """
    Demonstrates a potential issue related to unicode encoding of commas
    in email headers during address list folding.  This is a simplified
    representation of the potential vulnerability.
    """

    full_address = email.utils.formataddr((display_name, email_address))
    header_value = email.header.Header(full_address, charset)

    # Simulate folding that *might* include a comma at the end of a line
    # and encode it incorrectly.  This is a simplified model and does
    # *not* directly replicate the exim bug, but illustrates a similar
    # encoding problem in a related context. The folding is simulated by manually formatting the string.

    # NOTE: This simplified example might not trigger the exact problem.
    # It is intended to provide an example of how encoding behavior *could*
    # have been mishandled. The exact scenario in CVE-2025-1795 involves
    # interaction with the exim MTA which is not replicated in this example.
    
    encoded_header = str(header_value)  # Encode the whole header

    print("Encoded Header (Potential Vulnerability):", encoded_header)

if __name__ == '__main__':
    display_name = "Some User with Unicode Name éàçüöß"
    email_address = "user@example.com"
    demonstrate_cve_2025_1795(display_name, email_address)


    #Example 2 with a long display name
    display_name = "VeryLongNameWithUnicodeCharacters éàçüöß that causes folding"
    email_address = "user@example.com"
    demonstrate_cve_2025_1795(display_name, email_address)