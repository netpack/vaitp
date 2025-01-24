
from . import config
from . import constants

def load(doc):
    code = config.retrieveBoilerplateFile(doc, "bs-extensions", allowLocal=constants.executeCode)
    if not code:
        return

    if constants.executeCode:
        compileString(code)