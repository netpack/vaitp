# Vulnerable Smart Contract Example Using # type: ignore due to Vyper programming language
from vyper import nonreentrant

@nonreentrant("")
def withdraw(amount: uint256):
    assert amount > 0
    # Logic to transfer funds
    send(msg.sender, amount)