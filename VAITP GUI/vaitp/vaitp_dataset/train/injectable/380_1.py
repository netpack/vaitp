import bson
from bson.dbref import DBRef
from bson.objectid import ObjectId

def safe_decode_dbref(dbref):
    try:
        if not isinstance(dbref, dict):
            raise ValueError("Invalid DBRef: Must be a dictionary")

        if '$ref' not in dbref or '$id' not in dbref:
            raise ValueError("Invalid DBRef: Missing '$ref' or '$id'")
            
        ref = dbref.get('$ref')
        id_value = dbref.get('$id')
        
        if not isinstance(ref, str):
            raise ValueError("Invalid DBRef: '$ref' must be a string")
        
        if not isinstance(id_value, (str, ObjectId)):
            raise ValueError("Invalid DBRef: '$id' must be a string or ObjectId")

        if isinstance(id_value, str):
            try:
              id_value = ObjectId(id_value)
            except:
              raise ValueError("Invalid DBRef: '$id' is not a valid ObjectId string")

        return DBRef(ref, id_value)

    except Exception as e:
        print(f"Error decoding DBRef: {e}")
        return None

# Example usage
dbref = {'$ref': 'collection_name', '$id': '6599b7b92e3a284c8886516f'}
result = safe_decode_dbref(dbref)
print(result)

dbref = {'$ref': 'collection_name', '$id': ObjectId('6599b7b92e3a284c8886516f')}
result = safe_decode_dbref(dbref)
print(result)
