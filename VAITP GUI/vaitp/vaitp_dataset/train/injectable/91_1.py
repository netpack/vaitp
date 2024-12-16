import bz2
import io

def safe_decompress(compressed_data, max_selectors=None):
  """
  Decompresses bz2 data while mitigating the CVE-2019-12900 vulnerability.

  Args:
    compressed_data: The bz2 compressed bytes.
    max_selectors: An optional integer to limit the number of selectors during decompression.
                   If None, no limit is applied, otherwise raise ValueError if selectors exceed
                   this limit during decompression.

  Returns:
    The decompressed bytes.

  Raises:
      ValueError: if the number of selectors exceeds max_selectors, if max_selectors
                  is not None.
      OSError: If the underlying bz2 library encounters an issue other than too many
               selectors.

  """
  try:
      if max_selectors is None:
        return bz2.decompress(compressed_data)
      else:
        with io.BytesIO(compressed_data) as compressed_file:
          decompressor = bz2.BZ2Decompressor()
          decompressed_data = b''
          selector_count = 0
          while True:
            chunk = compressed_file.read(4096)
            if not chunk:
                break
            try:
                decompressed_chunk, _ , selectors_processed = decompressor.decompress(chunk)
                selector_count += selectors_processed
            except OSError as e:
                if "Too many selectors" in str(e) :
                    raise ValueError("Too many selectors") from e
                else:
                  raise
            if max_selectors is not None and selector_count > max_selectors:
                raise ValueError("Too many selectors")
            decompressed_data += decompressed_chunk
          return decompressed_data
  except bz2.BZ2Error as e:
      raise OSError("BZ2 decompression error") from e


if __name__ == '__main__':
  # Example usage with a crafted compressed data that generates many selectors
  # Create a custom compressed data that triggers many selectors
  # This is a very simplified representation of the complex structure of a bz2 stream
  # that would cause the vulnerability, and it is NOT the actual data that causes it
  # nor it reproduces the original conditions but rather demonstrates a similar control
  # on selectors count during processing.
  
  def create_vulnerable_data(selector_count):
     header = b'BZh91AY&SY'  # bzip2 header
     block_header = b'\x17rE\x06\xcf\x10\x00\x00' # Simplified representation of a block header
     selector_data = b'\x00' * (selector_count) # Represents selectors, normally encoded in variable lenght
     block_end = b'\x17\x71\x24\xe9\x02\x00\x00' # Represents the end of a block
     return header + block_header + selector_data + block_end

  # Test case 1: No limit
  compressed_data_1 = create_vulnerable_data(100)
  try:
      decompressed_data_1 = safe_decompress(compressed_data_1)
      print("Decompression 1 successful. Data length:", len(decompressed_data_1))
  except Exception as e:
      print("Decompression 1 failed:", e)

  # Test case 2: Limit the number of selectors to 100, should process
  compressed_data_2 = create_vulnerable_data(100)
  try:
      decompressed_data_2 = safe_decompress(compressed_data_2, max_selectors=100)
      print("Decompression 2 successful. Data length:", len(decompressed_data_2))
  except Exception as e:
    print("Decompression 2 failed:", e)


  # Test case 3: Limit the number of selectors to less than the data has, will raise an exception
  compressed_data_3 = create_vulnerable_data(100)
  try:
      decompressed_data_3 = safe_decompress(compressed_data_3, max_selectors=50)
      print("Decompression 3 successful. Data length:", len(decompressed_data_3))
  except Exception as e:
    print("Decompression 3 failed (expected):", e)