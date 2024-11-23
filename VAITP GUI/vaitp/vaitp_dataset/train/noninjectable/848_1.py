import pickle
import sqlalchemy

# Assuming `session` is your SQLAlchemy session connected to the Superset metadata database

def persist_vulnerable_object(obj):
    # Serialize the object using pickle (vulnerable to arbitrary code execution)
    data = pickle.dumps(obj)
    
    # Store the serialized data in the database
    new_entry = YourModel(data=data)  # Replace YourModel with your actual model
    session.add(new_entry)
    session.commit()

# Example usage
user_input = {'key': 'value', '__reduce__': (os.system, ('echo Vulnerable!',))}  # Malicious input
persist_vulnerable_object(user_input)