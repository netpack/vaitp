import tensorflow as tf

def draw_bounding_boxes(boxes, image, colors):
    # This function now checks the last dimension of boxes
    # to prevent out-of-bounds access.
    boxes_shape = tf.shape(boxes)
    if tf.rank(boxes) < 2 or boxes_shape[-1] != 4:
        raise ValueError("Bounding boxes must be a tensor of shape [N, 4], but got shape {}".format(boxes_shape))
    return tf.raw_ops.DrawBoundingBoxesV2(boxes=boxes, image=image, colors=colors)

# Example usage with potential vulnerability
boxes = tf.constant([[0.1, 0.2, 0.5, 0.5], [0.3, 0.3, 0.6, 0.8]], dtype=tf.float32)  # Corrected input (last dimension == 4)
image = tf.zeros([100, 100, 3], dtype=tf.float32)  # Dummy image
colors = tf.constant([[1.0, 0.0, 0.0]], dtype=tf.float32)  # Red color

# Call the vulnerable function
output_image = draw_bounding_boxes(boxes, image, colors)