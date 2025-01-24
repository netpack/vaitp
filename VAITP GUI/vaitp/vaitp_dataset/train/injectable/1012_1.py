import rclpy
from rclpy.node import Node
from rclpy.exceptions import InvalidParameterException
import ipaddress

class SecureNode(Node):
    def __init__(self):
        super().__init__('secure_node')
        self.declare_parameter('allowed_ip', '127.0.0.1')
        allowed_ip_str = self.get_parameter('allowed_ip').get_parameter_value().string_value
        try:
            self.allowed_ip = ipaddress.ip_address(allowed_ip_str)
        except ValueError:
            self.get_logger().error(f"Invalid IP address provided: {allowed_ip_str}, using default 127.0.0.1")
            self.allowed_ip = ipaddress.ip_address('127.0.0.1')

    def is_authorized(self, client_ip):
        try:
            client_ip_obj = ipaddress.ip_address(client_ip)
            return client_ip_obj == self.allowed_ip
        except ValueError:
            self.get_logger().warn(f"Invalid IP address format: {client_ip}")
            return False

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