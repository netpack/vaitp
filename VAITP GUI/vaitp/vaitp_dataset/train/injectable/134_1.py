# This code uses the zipimport module to import a module from a zip file
# The zip file does not contain any malicious header with a negative data size value
# The zipimport module sanitizes the input and checks for integer overflow
# This prevents the heap overflow attack described in CVE-2016-4472

import zipimport
zip_file = "safe.zip" # The zip file with a valid data size value
zip_importer = zipimport.zipimporter(zip_file)
module = zip_importer.load_module("module") # This does not trigger the heap overflow