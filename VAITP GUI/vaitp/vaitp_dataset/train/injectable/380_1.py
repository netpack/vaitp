import bson

def safe_decode_dbref(dbref):
    try:
        # Attempt to decode the DBRef safely
        if not isinstance(dbref, dict):
            raise ValueError("Invalid DBRef: Must be a dictionary")
        
        if '$ref' not in dbref or '$id' not in dbref:
            raise ValueError("Invalid DBRef: Missing '$ref' or '$id'")
        
        # Perform additional checks as necessary
        # Decode the DBRef safely here
        return bson.decode_all(bson.BSON.encode(dbref))
    except Exception as e:
        # Handle the error gracefully
        print(f"Error decoding DBRef: {e}")
        return None

# Example usage
dbref = {'$ref': 'collection_name', '$id': 'some_id'}
result = safe_decode_dbref(dbref)
print(result)