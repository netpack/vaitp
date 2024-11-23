# Example of a vulnerable Vyper smart contract before version 0.3.8
# This is a simplified representation of the vulnerability
owner: public(address)
data: public(uint256)

@public
def set_data(new_data: uint256):
    self.data = new_data

@public
def set_owner(new_owner: address):
    self.owner = new_owner  # Vulnerable to overflow attack

# Fixed version in Vyper 0.3.8 and later
# The storage allocator now guards against allocation overflows

# Example of a fixed Vyper smart contract
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