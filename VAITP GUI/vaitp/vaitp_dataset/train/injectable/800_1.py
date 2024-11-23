import tensorflow as tf

# Example of a transposed convolution operation that could trigger the vulnerability
def vulnerable_transposed_convolution(input_shape, filters, kernel_size):
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=input_shape),
        tf.keras.layers.Conv2DTranspose(filters, kernel_size, padding='same', activation='relu')
    ])
    return model

# Fixed version with proper weight quantization handling
def fixed_transposed_convolution(input_shape, filters, kernel_size):
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=input_shape),
        tf.keras.layers.Conv2DTranspose(filters, kernel_size, padding='same', activation='relu', 
                                         kernel_quantizer=tf.quantization.quantize_weights)
    ])
    return model

# Example usage
input_shape = (32, 32, 3)  # Example input shape
filters = 16               # Number of filters
kernel_size = (3, 3)      # Kernel size

# Create a model using the fixed function
model = fixed_transposed_convolution(input_shape, filters, kernel_size)