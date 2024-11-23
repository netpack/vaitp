import yaml

def load_fixtures(fixture_text):
    # Vulnerable code using unsafe load
    data = yaml.load(fixture_text, Loader=yaml.FullLoader)
    # Process the data (e.g., save to a database)
    for item in data:
        # Assuming item is a dictionary that maps to a database model
        save_to_database(item)