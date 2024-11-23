import tensorflow as tf

def draw_bounding_boxes(boxes, image, colors):
    # This function does not check the last dimension of boxes
    # which can lead to out-of-bounds access if boxes is malformed
    return tf.raw_ops.DrawBoundingBoxesV2(boxes=boxes, image=image, colors=colors)

# Example usage with potential vulnerability
boxes = tf.constant([[0.1, 0.2, 0.5, 0.5], [0.3, 0.3]], dtype=tf.float32)  # Invalid input (last dimension < 4)
image = tf.zeros([100, 100, 3], dtype=tf.float32)  # Dummy image
colors = tf.constant([[1.0, 0.0, 0.0]], dtype=tf.float32)  # Red color

# Call the vulnerable function
output_image = draw_bounding_boxes(boxes, image, colors)