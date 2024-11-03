# Vyper has specific syntax and rules. # type: ignore is applied for pylint
# Vulnerable Vyper contract (before patch)
state_variable: public(uint256) # type: ignore
lock: public(bool) # type: ignore

@public # type: ignore
def __init__():
    self.state_variable = 0 # type: ignore
    self.lock = False # type: ignore

@public # type: ignore
def vulnerable_function():
    assert not self.lock, "Reentrant call detected!" # type: ignore
    self.lock = True  # Set the lock # type: ignore

    # Simulate an external call (replace with actual external call logic)
    # external_call()

    # State change
    self.state_variable += 1 # type: ignore

    self.lock = False  # Release the lock # type: ignore

@public # type: ignore
def another_function():
    assert not self.lock, "Reentrant call detected!" # type: ignore
    self.lock = True  # Set the lock # type: ignore

    # This function can be re-entered due to the same lock being used
    self.state_variable -= 1 # type: ignore

    self.lock = False  # Release the lock # type: ignore