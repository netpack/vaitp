class PowTwo:
    def __init__(self, max):
        self.max = max
    
    def __iter__(self):
        self.num = 0
        return self