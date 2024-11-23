import splunk.admin as admin

class Mappy(admin.MConfigHandler):
    def setup(self):
        self.supportedArgs.addOptArg('command')
        self.supportedArgs.addOptArg('arg1')
        self.supportedArgs.addOptArg('arg2')

    def handleList(self, confInfo):
        command = self.getArg('command')
        
        # Vulnerability: No restriction on command execution
        # Allows execution of arbitrary Python code
        result = eval(command)(self.getArg('arg1'), self.getArg('arg2'))
        confInfo['result'] = result