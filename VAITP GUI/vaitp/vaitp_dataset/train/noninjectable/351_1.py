class KeyParser:
    def parse_key(self, key_data):
        expected_length = 10
        try:
            # Assume some logic to parse the key
            if len(key_data) < expected_length:
                raise ValueError(f"Key field too short: {key_data}")  # Exposing sensitive data
        except ValueError as e:
            print(f"Error parsing key: {e}")

# Example usage
parser = KeyParser()
parser.parse_key("short_key_data")