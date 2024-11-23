import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

class VulnerableGuakeService(dbus.service.Object):
    def __init__(self, bus_name):
        self.bus_name = bus_name
        dbus.service.Object.__init__(self, bus_name, '/com/example/guake')

    @dbus.service.method('com.example.guake', in_signature='s', out_signature='s')
    def execute_command(self, command):
        # Directly execute the command without validation
        import subprocess
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus_name = dbus.service.BusName('com.example.guake', bus=dbus.SessionBus())
    service = VulnerableGuakeService(bus_name)
    loop = GLib.MainLoop()
    loop.run()