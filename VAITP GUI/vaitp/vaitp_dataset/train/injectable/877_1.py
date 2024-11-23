import AccessControl

class SafeFormatter(string.Formatter):
    def get_value(self, key, args, kwargs):
        # Use policy restricted access methods
        if isinstance(key, str):
            return kwargs.get(key, None)
        return super().get_value(key, args, kwargs)

def safe_format_map(format_string, mapping):
    formatter = SafeFormatter()
    return formatter.vformat(format_string, (), mapping)

# Example usage
try:
    user_input = "{user_attr}"  # Untrusted input
    context = {'user_attr': 'Sensitive data'}  # Context that should be protected
    result = safe_format_map(user_input, context)
    print(result)
except Exception as e:
    print(f"Error: {e}")