# Import the multibytecodec_support module
import test.multibytecodec_support as mbc_support

# Define a URL that points to a benign server
# The server will send a valid HTTP response
# The response will contain a reference file for the CJK codec tests
url = "http://example.com/refex_euc_kr.txt"

# Call the test_decode_refex function with the URL
# This will not trigger the vulnerability in the multibytecodec_support.py module
# The eval() function will only process the reference file from the HTTP response
mbc_support.test_decode_refex("euc_kr", url)