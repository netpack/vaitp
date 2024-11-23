def vulnerable_decode_escape(input_string):
    # This function simulates the vulnerable behavior of decoding escape sequences
    # without proper checks for integer overflow.
    return input_string.encode('utf-8').decode('unicode_escape')

if __name__ == "__main__":
    # Example input that could lead to an integer overflow
    input_string = "some_string_with_escape_sequences" + "\x7f" * (2**31)  # Simulate large input

    try:
        result = vulnerable_decode_escape(input_string)
        print("Decoded string:", result)
    except Exception as e:
        print("Error:", e)