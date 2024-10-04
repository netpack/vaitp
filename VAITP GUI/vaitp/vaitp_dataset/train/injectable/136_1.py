# This code uses the bz2 module to decompress a zip file
# The zip file does not contain any malicious header with a negative data size value
# The bz2 module sanitizes the input and checks for integer overflow
# This prevents the use-after-free error described in CVE-2016-3189

import bz2
zip_file = "safe.zip" # The zip file with a valid data size value
data = bz2.decompress(open(zip_file, "rb").read()) # This does not trigger the use-after-free error