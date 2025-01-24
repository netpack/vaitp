owner: public(address)
data: public(uint256)

@public
def set_data(new_data: uint256):
    assert new_data >= 0  # Guard against invalid data
    self.data = new_data

@public
def set_owner(new_owner: address):
    assert new_owner != ZERO_ADDRESS  # Prevent setting owner to zero address
    self.owner = new_owner  # Safe assignment
