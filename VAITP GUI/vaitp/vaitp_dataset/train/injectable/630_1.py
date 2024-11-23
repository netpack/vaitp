import os

def secure_console_module():
    console_module_file = '/config/ConsoleModuleUnlock.txt'
    admin_tool_file = '/config/admin/admintool.xml'

    # Check if the Console module unlock file exists
    if os.path.exists(console_module_file):
        raise PermissionError("Access to Console module is restricted. Please remove ConsoleModuleUnlock.txt.")

    # Check if the admin tool file has been tampered with
    with open(admin_tool_file, 'r') as file:
        content = file.read()
        if '<ConsoleModule enabled="true">' in content:
            raise PermissionError("Console module is disabled. Please fix admintool.xml.")

# Call the function to enforce security checks
secure_console_module()