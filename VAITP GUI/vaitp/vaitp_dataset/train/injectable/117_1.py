import sys

def safe_decode_escape(input_string):
    try:
        # Example of a safe decoding function that checks for integer overflow
        decoded_string = input_string.encode('utf-8').decode('unicode_escape')
        return decoded_string
    except (UnicodeDecodeError, OverflowError) as e:
        print("Error decoding string:", e)
        return None

if __name__ == "__main__":
    # Example input that could have previously caused an overflow
    input_string = "some_string_with_escape_sequences"
    
    result = safe_decode_escape(input_string)
    if result is not None:
        print("Decoded string:", result)