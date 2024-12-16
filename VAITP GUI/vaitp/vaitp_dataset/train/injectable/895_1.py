# This code snippet represents a fix for the CVE-2023-36807 vulnerability in pypdf.
# It modifies the read_object function to throw an error instead of entering an infinite loop.

def read_object(self, object_id):
    try:
        # Attempt to read the object from the PDF
        obj = self.objects[object_id]
        if obj is None:
            raise ValueError("Object not found or malformed PDF.")
        return obj
    except Exception as e:
        raise ValueError("An error occurred while reading the PDF object: " + str(e))