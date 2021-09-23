# based on https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html
s = """
(lambda fc=(
    lambda n: [

            c for c in ().__class__.__base__.__subclasses__()
            if c.__name__ == 'catch_warnings'

        ][0]()._module.__builtins__
    ):
    fc("function")(
        
        fc("code")(
            0,0,0,0,0,0,b'1',(),(),(),"","",0,b'1'
        ),{}
    )()
)()
"""
eval(s, {'__builtins__':{}})

#seg fault