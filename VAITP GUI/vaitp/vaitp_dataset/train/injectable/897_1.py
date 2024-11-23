import tensorflow as tf

def safe_sparse_dense_cwise_mul(sparse_tensor, dense_tensor):
    # Validate dimensions before proceeding
    sparse_shape = sparse_tensor.shape
    dense_shape = dense_tensor.shape

    # Ensure that the dimensions are compatible
    if sparse_shape[1] != dense_shape[0]:
        raise ValueError("Incompatible dimensions: "
                         f"sparse tensor's second dimension ({sparse_shape[1]}) "
                         f"must match dense tensor's first dimension ({dense_shape[0]}).")

    # Proceed with the operation if dimensions are valid
    return tf.raw_ops.SparseDenseCwiseMul(sparse_indices=sparse_tensor.indices,
                                           sparse_values=sparse_tensor.values,
                                           sparse_shape=sparse_shape,
                                           dense=dense_tensor)

# Example usage
sparse_tensor = tf.sparse.SparseTensor(indices=[[0, 0], [1, 2]], values=[1.0, 2.0], dense_shape=[2, 3])
dense_tensor = tf.constant([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])

result = safe_sparse_dense_cwise_mul(sparse_tensor, dense_tensor)
print(result)