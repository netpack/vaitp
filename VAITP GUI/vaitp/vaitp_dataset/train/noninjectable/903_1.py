import tensorflow as tf

def vulnerable_ragged_bincount(splits, values, num_bins):
    # Assume splits is not validated and can be any tensor
    # This may lead to out-of-bounds access
    batch_idx = 0
    while batch_idx < tf.shape(splits)[0]:
        # Potentially unsafe access to splits
        if splits[batch_idx] == 7:  # Simulating an attack
            break
        batch_idx += 1

    # This can lead to writing to out(-1, bin), causing a buffer overflow
    out = tf.zeros([num_bins], dtype=tf.int32)
    out[-1] += 1  # Unsafe write

    return out

# Example usage (this could trigger the vulnerability)
splits = tf.constant([7])  # Malicious input
values = tf.constant([0, 1, 2])
num_bins = 3

output = vulnerable_ragged_bincount(splits, values, num_bins)
print(output)