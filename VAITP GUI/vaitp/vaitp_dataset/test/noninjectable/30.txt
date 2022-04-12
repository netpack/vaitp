def __call__(self, econtext):
    var1 = []
    if isinstance(self._expr, str):
        evaluate = econtext.somevalue
    else:
        evaluate = econtext.othervalue
    for var in self._vars:
        v = evaluate(var)
        var1.append(v)
    return self._expr % tuple(var1)
