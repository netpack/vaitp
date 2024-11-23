import rclpy
from rclpy.node import Node

class VulnerableNode(Node):
    def __init__(self):
        super().__init__('vulnerable_node')

    def handle_request(self, request, client_ip):
        # No authorization check, allowing any client to access this method
        return "Request handled successfully"

def main(args=None):
    rclpy.init(args=args)
    vulnerable_node = VulnerableNode()
    
    # Example of handling a request
    client_ip = "192.168.1.1"  # This would be dynamically determined in a real application
    response = vulnerable_node.handle_request("some_request", client_ip)
    vulnerable_node.get_logger().info(response)

    rclpy.spin(vulnerable_node)
    vulnerable_node.destroy_node()
    rclpy.shutdown()

if __name__ == '__main__':
    main()