import pickle
import sqlalchemy

# Assuming `session` is your SQLAlchemy session connected to the Superset metadata database

def safe_load(data):
    # Only allow loading of safe types
    allowed_classes = (dict, list, str, int, float, bool)
    obj = pickle.loads(data)
    
    if not isinstance(obj, allowed_classes):
        raise ValueError("Unsafe object type detected!")
    
    return obj

def persist_safe_object(obj):
    # Serialize the object safely
    safe_data = pickle.dumps(obj)
    
    # Store the safe_data in the database
    new_entry = YourModel(data=safe_data)  # Replace YourModel with your actual model
    session.add(new_entry)
    session.commit()

# Example usage
try:
    user_input = {'key': 'value'}  # Replace with actual user input
    persist_safe_object(user_input)
except Exception as e:
    print(f"Error: {e}")