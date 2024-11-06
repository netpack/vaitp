import os
import sys

def load_plugin(plugin_name):
    # Vulnerable: Directly appending to sys.path
    sys.path.append(os.path.join(os.getcwd(), 'plugins'))
    
    try:
        # Attempt to import the plugin
        plugin = __import__(plugin_name)
        return plugin
    except ImportError:
        print(f"Failed to load plugin: {plugin_name}")

# Usage
plugin_name = 'malicious_plugin'  # This could be a malicious module
load_plugin(plugin_name)