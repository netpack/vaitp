def process_data(data):
    # Hypothetical function that processes system data
    for item in data:
        obj = create_object(item)  # Create a new object
        ref_count = get_ref_count(obj)

        if ref_count > 1:
            # Improperly handling reference counts could lead to a double free
            free_object(obj)  # Free the object
            free_object(obj)  # Double free occurs here

def create_object(item):
    # Creates and returns an object for the given item
    return item

def get_ref_count(obj):
    # Hypothetical function to get the reference count of an object
    return 2  # Simulating a reference count greater than 1

def free_object(obj):
    # Function to free the object
    print(f"Freeing object: {obj}")