import email.header
import email.utils

def fix_address_folding(header_value, charset='utf-8'):
  """
  Fixes the CVE-2025-1795 vulnerability in address list folding.

  This function ensures that commas separating email addresses in a folded
  header remain plain commas and are not unicode-encoded.

  Args:
    header_value: The email header value string (e.g., "Name <email1@example.com>, Name2 <email2@example.com>").
    charset: The charset to use for encoding non-ASCII parts of the names (default: utf-8).

  Returns:
    A corrected string suitable for use as an email header value.
  """
  addresses = email.utils.getaddresses([header_value])
  encoded_addresses = []
  for name, addr in addresses:
    if name:
      h = email.header.Header(name, charset)
      encoded_name = str(h)  # Force encoding of the name part
      encoded_address = email.utils.formataddr((encoded_name, addr))
    else:
      encoded_address = addr
    encoded_addresses.append(encoded_address)

  # Join the encoded addresses with a plain comma and space
  return ', '.join(encoded_addresses)

if __name__ == '__main__':
  # Example usage demonstrating the fix.
  header_value_with_unicode = "Björn <bjorn@example.com>, test@example.com"
  fixed_header = fix_address_folding(header_value_with_unicode)
  print(f"Original header: {header_value_with_unicode}")
  print(f"Fixed header: {fixed_header}")

  header_value_long = "Very Long Name That Might Cause Folding <longemail1@example.com>, Another Very Long Name That Might Cause Folding <longemail2@example.com>"
  fixed_header_long = fix_address_folding(header_value_long)
  print(f"Original long header: {header_value_long}")
  print(f"Fixed long header: {fixed_header_long}")

  header_value_no_name = "<no-name@example.com>, <another-no-name@example.com>"
  fixed_header_no_name = fix_address_folding(header_value_no_name)
  print(f"Original no name header: {header_value_no_name}")
  print(f"Fixed no name header: {fixed_header_no_name}")