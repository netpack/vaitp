class Validator:
    def __init__(self, validators):
        self.validators = validators

    def validate(self, value):
        # Ensure that the value is not None or an invalid type
        if value is None or not isinstance(value, (int, float)):
            return False

        for validator in self.validators:
            if not validator(value):
                return False
        return True

def is_positive(value):
    return value > 0

def is_even(value):
    return value % 2 == 0

# Chained validators
validators = Validator([is_positive, is_even])

# Example usage
value = 3
if validators.validate(value):
    print(f"{value} is valid")
else:
    print(f"{value} is invalid")