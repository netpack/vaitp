import rclpy
from rclpy.node import Node
from rclpy.exceptions import InvalidParameterException

class SecureNode(Node):
    def __init__(self):
        super().__init__('secure_node')
        self.declare_parameter('allowed_ip', '127.0.0.1')
        self.allowed_ip = self.get_parameter('allowed_ip').get_parameter_value().string_value

    def is_authorized(self, client_ip):
        return client_ip == self.allowed_ip

    def handle_request(self, request, client_ip):
        if not self.is_authorized(client_ip):
            self.get_logger().warn(f"Unauthorized access attempt from {client_ip}")
            return "Unauthorized access"
        
        # Handle the request if authorized
        return "Request handled successfully"

def main(args=None):
    rclpy.init(args=args)
    secure_node = SecureNode()
    
    # Example of handling a request
    client_ip = "192.168.1.1"  # This would be dynamically determined in a real application
    response = secure_node.handle_request("some_request", client_ip)
    secure_node.get_logger().info(response)

    rclpy.spin(secure_node)
    secure_node.destroy_node()
    rclpy.shutdown()

if __name__ == '__main__':
    main()