# Vulnerable Vyper code using create_copy_of Using # type: ignore due to Vyper programming language
@public
def copy_contract(salt: uint256):
    # This call can lead to memory corruption if 'salt' is a complex expression
    create_copy_of(my_contract, salt)