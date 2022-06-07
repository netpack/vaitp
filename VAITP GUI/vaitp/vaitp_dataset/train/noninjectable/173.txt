def outer_function():
    global a
    a = 20

    def inner_function():
        global a
        a = 30
        print('a =', a)