# Vyper has specific syntax and rules. # type: ignore is applied for pylint
# Patched Vyper contract (after patch)
state_variable: public(uint256)
lock_vulnerable: public(bool)
lock_another: public(bool)

@public
def __init__():
    self.state_variable = 0
    self.lock_vulnerable = False
    self.lock_another = False

@public
def safe_function():
    assert not self.lock_vulnerable, "Reentrant call detected!"
    self.lock_vulnerable = True  # Set the lock

    # Simulate an external call (replace with actual external call logic)
    # external_call()

    # State change
    self.state_variable += 1

    self.lock_vulnerable = False  # Release the lock

@public
def another_function():
    assert not self.lock_another, "Reentrant call detected!"
    self.lock_another = True  # Set the lock

    # This function cannot be re-entered while safe_function is executing
    self.state_variable -= 1

    self.lock_another = False  # Release the lock