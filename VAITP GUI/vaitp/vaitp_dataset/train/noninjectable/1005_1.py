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