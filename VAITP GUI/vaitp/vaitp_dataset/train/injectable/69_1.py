def convert_to_int(text):
    try:
        return int(text)
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        return None

user_input = "1e308"
result = convert_to_int(user_input)
if result is not None:
    print("Converted number:", result)