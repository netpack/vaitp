import os
import xml.etree.ElementTree as ET

def secure_console_module():
    console_module_file = '/config/ConsoleModuleUnlock.txt'
    admin_tool_file = '/config/admin/admintool.xml'

    # Check if the Console module unlock file exists
    if os.path.exists(console_module_file):
        raise PermissionError("Access to Console module is restricted. Please remove ConsoleModuleUnlock.txt.")

    # Check if the admin tool file has been tampered with
    try:
        tree = ET.parse(admin_tool_file)
        root = tree.getroot()
        console_module_element = root.find('.//ConsoleModule')
        if console_module_element is not None and console_module_element.get('enabled') == 'true':
              raise PermissionError("Console module is disabled. Please fix admintool.xml.")
    except (ET.ParseError, FileNotFoundError):
        raise PermissionError("Error parsing admintool.xml or file not found.")


# Call the function to enforce security checks
secure_console_module()