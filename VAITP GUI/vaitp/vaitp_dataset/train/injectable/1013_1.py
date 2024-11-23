import rclpy
from rclpy.node import Node

class SecureNode(Node):
    def __init__(self):
        super().__init__('secure_node')

    def validate_node_name(self, node_name):
        # Implement validation logic to ensure only authorized nodes can be created
        allowed_node_names = ['secure_node', 'trusted_node']
        if node_name not in allowed_node_names:
            raise ValueError(f"Unauthorized node name: {node_name}")

    def create_node(self, node_name):
        self.validate_node_name(node_name)
        # Proceed to create the node if validation passes
        return rclpy.create_node(node_name)

def main(args=None):
    rclpy.init(args=args)
    secure_node = SecureNode()
    
    try:
        # Attempt to create a node
        new_node = secure_node.create_node('malicious_node')  # This will raise an error
    except ValueError as e:
        secure_node.get_logger().error(str(e))
    
    rclpy.spin(secure_node)
    secure_node.destroy_node()
    rclpy.shutdown()

if __name__ == '__main__':
    main()