import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import subprocess
import shlex

class SecureGuakeService(dbus.service.Object):
    def __init__(self, bus_name):
        self.bus_name = bus_name
        dbus.service.Object.__init__(self, bus_name, '/com/example/guake')

    @dbus.service.method('com.example.guake', in_signature='s', out_signature='s')
    def execute_command(self, command):
        # Validate the command before execution
        if self.is_command_safe(command):
            # Execute the command securely
            return self.run_command(command)
        else:
            raise dbus.DBusException('Command not allowed')

    def is_command_safe(self, command):
        # Implement logic to check for allowed commands
        allowed_commands = ['ls', 'pwd']  # Example of safe commands
        return command in allowed_commands

    def run_command(self, command):
        # Safely execute the command and return the output
        try:
            command_list = shlex.split(command)
            result = subprocess.run(command_list, capture_output=True, text=True, check=True)
            return result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
             return str(e)

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus_name = dbus.service.BusName('com.example.guake', bus=dbus.SessionBus())
    service = SecureGuakeService(bus_name)
    loop = GLib.MainLoop()
    loop.run()