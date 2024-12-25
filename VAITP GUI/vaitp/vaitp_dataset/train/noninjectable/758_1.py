import splunk.admin as admin
import subprocess

class Mappy(admin.MConfigHandler):
    def setup(self):
        self.supportedArgs.addOptArg('command')
        self.supportedArgs.addOptArg('arg1')
        self.supportedArgs.addOptArg('arg2')

    def handleList(self, confInfo):
        command = self.getArg('command')
        arg1 = self.getArg('arg1')
        arg2 = self.getArg('arg2')
        
        # Vulnerability: No restriction on command execution
        # Allows execution of arbitrary system commands, not Python code
        # Attempt to execute command using subprocess.run, which is safer than eval
        try:
            if command:
                if arg1 and arg2:
                  process = subprocess.run([command, arg1, arg2], capture_output=True, text=True, check=True)
                elif arg1:
                    process = subprocess.run([command, arg1], capture_output=True, text=True, check=True)
                else:
                    process = subprocess.run([command], capture_output=True, text=True, check=True)

                result = process.stdout
            else:
                result = "No command provided."
        except subprocess.CalledProcessError as e:
            result = f"Error executing command: {e.stderr}"
        except FileNotFoundError:
           result = f"Command '{command}' not found"
        except Exception as e:
           result = f"An unexpected error occurred: {e}"

        confInfo['result'] = result