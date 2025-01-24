import sys
import json
try:
    input_str = sys.argv[1]
    data = json.loads(input_str)
    if isinstance(data, dict):
      print(data)
    elif isinstance(data, list):
      print(data)
    else:
        print("Invalid input format")

except (IndexError, json.JSONDecodeError):
    print("Invalid input")
except Exception:
    print("An unexpected error occurred.")