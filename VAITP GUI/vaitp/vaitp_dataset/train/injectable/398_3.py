
@public
def safe_copy_contract(salt: uint256):
    cached_salt = salt
    new_contract_address = create_copy_of(my_contract, cached_salt)

    assert new_contract_address != EMPTY_ADDRESS