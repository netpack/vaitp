# Example of a vulnerable Vyper smart contract that demonstrates CVE-2021-41121

class MyStruct:
    def __init__(self, value):
        self.value = value


def my_function():
    # Vulnerable usage of a function call inside a literal struct
    my_struct = MyStruct(some_function_call())

def some_function_call() -> int:
    # Function that returns a value
    return 42