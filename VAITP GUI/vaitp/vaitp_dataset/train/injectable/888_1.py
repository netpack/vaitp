
import tensorflow as tf
import numpy as np
import tempfile
import os

# Create a temporary memory-mapped file
temp_file = tempfile.NamedTemporaryFile(delete=False)
data = np.random.rand(10).astype(np.float32)  # Create a float array
data.tofile(temp_file.name)  # Write data to the file

# Use tf.io.FixedLenRecordDataset to create a dataset from the file, then use take(1) to get a single element and then convert it to a tensor.
try:
    dataset = tf.data.FixedLengthRecordDataset(temp_file.name, 4 * 10)
    tensor = tf.io.parse_tensor(dataset.take(1).get_single_element(), tf.float32)
    print(tensor)
except Exception as e:
    if isinstance(e, tf.errors.NotFoundError):  # Catch the TF error
        print(f"File not found: {temp_file.name}")
    else:
        print(f"Error occurred: {e}")


# Clean up
temp_file.close()
os.unlink(temp_file.name)