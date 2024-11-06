import os
import sys

def load_plugin(plugin_name):
    # Define a safe directory for plugins
    safe_plugin_dir = os.path.join(os.getcwd(), 'plugins')
    
    # Check if the plugin directory exists
    if not os.path.isdir(safe_plugin_dir):
        print("Plugin directory does not exist.")
        return None
    
    # Check if the requested plugin is safe
    plugin_path = os.path.join(safe_plugin_dir, f"{plugin_name}.py")
    if not os.path.isfile(plugin_path):
        print(f"Plugin {plugin_name} does not exist in the safe directory.")
        return None
    
    # Add the safe plugin directory to sys.path
    sys.path.append(safe_plugin_dir)
    
    try:
        # Attempt to import the plugin
        plugin = __import__(plugin_name)
        return plugin
    except ImportError:
        print(f"Failed to load plugin: {plugin_name}")

# Usage
plugin_name = 'safe_plugin'  # This should be a known safe module
load_plugin(plugin_name)