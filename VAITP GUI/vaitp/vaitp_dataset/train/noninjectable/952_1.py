import configparser

class Page:
    def __init__(self, locator_file):
        self.locators = self.__load_locators(locator_file)

    def __load_locators(self, locator_file):
        config = configparser.ConfigParser()
        config.read(locator_file)
        locators = {}
        
        for section in config.sections():
            for key, value in config.items(section):
                locators[key] = value
        return locators

    def __locator__(self, locator_name: str):
        # Vulnerable code: directly evaluating the locator value
        return eval(self.locators.get(locator_name))

# Usage
# page = Page('locators.ini')