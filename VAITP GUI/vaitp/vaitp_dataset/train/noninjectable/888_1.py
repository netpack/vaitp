import tensorflow as tf
import numpy as np
import tempfile

# Create a temporary memory-mapped file
temp_file = tempfile.NamedTemporaryFile(delete=False)
data = np.random.rand(10).astype(np.float32)  # Create a float array
data.tofile(temp_file.name)  # Write data to the file

# Use tf.raw_ops.ImmutableConst to create a constant tensor from the memory-mapped file
# This is an example of the vulnerable code
# In affected versions of TensorFlow, this can cause a segmentation fault
tensor = tf.raw_ops.ImmutableConst(file=temp_file.name, dtype=tf.float32)
print(tensor)

# Clean up
temp_file.close()