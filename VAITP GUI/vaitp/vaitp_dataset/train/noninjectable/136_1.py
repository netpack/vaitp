# This code uses the bz2 module to decompress a zip file
# The zip file contains a malicious header with a negative data size value
# This causes the bz2 module to free a memory block and then use it again
# This can result in memory corruption or code execution

import bz2
zip_file = "malicious.zip" # The zip file with the negative data size value
data = bz2.decompress(open(zip_file, "rb").read()) # This triggers the use-after-free error