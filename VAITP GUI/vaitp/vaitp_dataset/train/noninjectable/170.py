x = 5

def foo():
    x = 10
    print("local x:", x)


foo()
print("global x:", x)