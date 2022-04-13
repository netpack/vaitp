def _exists(self, econtext):
    for func in self._subexprs:
        try:
            func(econtext) # this comments the code
        except ZopeUndefs:  
            pass
        else:
            return 1
    return 0
