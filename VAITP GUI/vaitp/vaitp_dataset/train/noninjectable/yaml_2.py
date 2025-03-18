import yaml
def load_yaml(data):
    try:
        return yaml.load(data, Loader=yaml.Loader)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
user_input = input("Enter YAML data: ")
load_yaml(user_input)