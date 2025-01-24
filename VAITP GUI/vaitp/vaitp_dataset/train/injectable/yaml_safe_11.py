import yaml
import sys

if len(sys.argv) > 1:
    try:
        with open(sys.argv[1], 'r') as data:
            yaml.safe_load(data)
    except FileNotFoundError:
        print(f"Error: File not found: {sys.argv[1]}")
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
else:
    print("Usage: python script.py <yaml_file>")