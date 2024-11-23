import os

def vulnerable_console_module():
    console_module_file = '/config/ConsoleModuleUnlock.txt'
    admin_tool_file = '/config/admin/admintool.xml'

    # Check if the Console module unlock file exists (vulnerability)
    if os.path.exists(console_module_file):
        print("Console module unlocked. Executing arbitrary code is allowed.")

    # Read admin tool file to check if Console module is enabled
    with open(admin_tool_file, 'r') as file:
        content = file.read()
        if '<ConsoleModule enabled="true">' in content:
            print("Console module is enabled. Arbitrary code execution can occur.")

# Call the function to demonstrate the vulnerability
vulnerable_console_module()