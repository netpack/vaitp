# Example of a vulnerable Vyper smart contract that demonstrates CVE-2021-41121

struct MyStruct:
    value: uint256

@public
def my_function():
    # Vulnerable usage of a function call inside a literal struct
    my_struct: MyStruct = MyStruct({value: some_function_call()})

def some_function_call() -> uint256:
    # Function that returns a value
    return 42