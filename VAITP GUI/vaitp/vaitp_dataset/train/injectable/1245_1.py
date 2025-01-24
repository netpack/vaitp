import zlib
import os
import io
from zipfile import ZipFile, ZipInfo
import struct


def fixed_zip_open_new_file_in_zip4_64(zip_file, filename, comment=None, extra=None, file_date=(1980, 1, 1, 0, 0, 0),
                                      compress_type=zlib.DEFLATED, compresslevel=None,
                                      create_system=0, external_attr=0, flag_bits=0):

    """
    A reimplementation of the vulnerable MiniZip's zipOpenNewFileInZip4_64 function, but mitigating CVE-2023-45853.
    This version limits the filename, comment, and extra field lengths to prevent overflows
    """

    if not isinstance(filename, bytes):
      filename = filename.encode("utf-8")


    if comment is not None and not isinstance(comment, bytes):
      comment = comment.encode("utf-8")
    
    if extra is not None and not isinstance(extra, bytes):
        extra = extra.encode("utf-8")


    max_len = 65535  # Maximum length for filename, comment, and extra field, as enforced by ZIP standard
    
    filename = filename[:max_len] if filename else b""
    comment = comment[:max_len] if comment else b""
    extra = extra[:max_len] if extra else b""
    
    
    
    
    zinfo = ZipInfo(filename=filename, date_time=file_date)
    zinfo.compress_type = compress_type
    zinfo.comment = comment
    zinfo.extra = extra
    zinfo.create_system = create_system
    zinfo.external_attr = external_attr
    zinfo.flag_bits = flag_bits

    with zip_file.open(zinfo, mode='w', force_zip64=True) as f:
      yield f # Yield the file-like object to enable writing to it

def create_and_write_zip(zip_filename, filename_in_zip, data):
    """
    Demonstrates the usage of the fixed implementation.
    """
    with ZipFile(zip_filename, 'w', zlib.ZIP_DEFLATED, True) as zipf:
         
      
      with fixed_zip_open_new_file_in_zip4_64(zipf, filename=filename_in_zip) as file_handle:
            file_handle.write(data)
       


if __name__ == '__main__':
    
    # Generate long data that simulates the exploit conditions (long filename, comment, or extra field).
    long_name = b"a"* 70000
    normal_data = b"This is test data"
    
    
    # Test with long filename
    create_and_write_zip("fixed_test_long_name.zip", long_name, normal_data)

    # Test with normal length
    create_and_write_zip("fixed_test_normal.zip", "normal_file.txt", normal_data)

    print("Zip files created. Check 'fixed_test_long_name.zip' and 'fixed_test_normal.zip'")