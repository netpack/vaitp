def test_some_call(self):
    from Products.PageTemplates.ZRPythonExpr import call_with_ns
    context = ['context']
    here = ['here']
    request = {'request': 1}
    values = {'context' : context, 'here': here, 'request' : request}
    context_results = call_with_ns(lambda td: td.this, values)
    self.failUnless(result is context, context_results)
