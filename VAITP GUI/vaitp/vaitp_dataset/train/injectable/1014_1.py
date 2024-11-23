import rclpy
from rclpy.node import Node
from std_msgs.msg import String

class SafeNode(Node):
    def __init__(self):
        super().__init__('safe_node')
        self.publisher_ = self.create_publisher(String, 'safe_topic', 10)
        self.subscription = self.create_subscription(
            String,
            'unsafe_topic',
            self.listener_callback,
            10)
        self.subscription  # prevent unused variable warning

    def listener_callback(self, msg):
        # Implement input validation to prevent DoS
        if self.is_valid_message(msg.data):
            self.get_logger().info(f'Received: "{msg.data}"')
            # Process the message safely
        else:
            self.get_logger().warning('Received invalid message, ignoring.')

    def is_valid_message(self, message):
        # Simple validation logic (e.g., length check, content check)
        return isinstance(message, str) and len(message) < 256

def main(args=None):
    rclpy.init(args=args)
    safe_node = SafeNode()
    rclpy.spin(safe_node)
    safe_node.destroy_node()
    rclpy.shutdown()

if __name__ == '__main__':
    main()