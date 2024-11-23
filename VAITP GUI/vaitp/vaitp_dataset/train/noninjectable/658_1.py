import dbus
import pickle

class FirewallConfig:
    def __init__(self):
        # Initialize firewall configuration
        pass

    def set_config(self, serialized_data):
        # Unsafe use of pickle for deserialization
        try:
            config = pickle.loads(serialized_data)
            # Process the config
        except Exception as e:
            print(f"Error processing configuration: {e}")

# Example of how to expose the method via D-Bus
def main():
    bus = dbus.SystemBus()
    obj = FirewallConfig()
    bus.export('/com/example/FirewallConfig', obj)

if __name__ == "__main__":
    main()