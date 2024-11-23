import tensorflow as tf

def safe_sdca_optimizer(learning_rate, num_iterations, *args):
    # Validate that all required arguments are provided
    if learning_rate is None or num_iterations is None:
        raise ValueError("Learning rate and number of iterations must be provided.")

    # Check that additional arguments meet expected criteria
    for arg in args:
        if arg is None:
            raise ValueError("All additional arguments must be non-null.")

    # Proceed with the optimizer if all checks pass
    optimizer = tf.raw_ops.SdcaOptimizer(
        learning_rate=learning_rate,
        num_iterations=num_iterations,
        *args
    )
    return optimizer

# Example usage
try:
    result = safe_sdca_optimizer(0.01, 100, None)  # This will raise an error
except ValueError as e:
    print(e)