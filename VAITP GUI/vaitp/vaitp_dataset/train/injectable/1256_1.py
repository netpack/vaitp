def execute_precompile(precompile_id, gas_available, data):
    """
    Simulates the execution of a precompile.

    Args:
        precompile_id: The ID of the precompile (1 for ecrecover, 4 for identity).
        gas_available: The amount of gas available for the precompile call.
        data: The data to pass to the precompile.

    Returns:
        A tuple: (success, gas_used, output)
    """

    if precompile_id == 1:  # ecrecover
        if gas_available < 3000: # Example gas cost for ecrecover
            return False, 0, b'' # Simulate failed precompile due to insufficient gas
        # Simulate ecrecover logic (actual logic is more complex)
        # ...
        success = True # Simplified success outcome for this example
        output = b"recovered address"  # Example output
        gas_used = 3000
        return success, gas_used, output
    elif precompile_id == 4:  # identity
        if gas_available < 100: # Example gas cost for identity
            return False, 0, b'' # Simulate failed precompile due to insufficient gas
        # Simulate identity logic
        output = data
        gas_used = 100
        success = True
        return success, gas_used, output
    else:
        return False, 0, b'' # Unknown precompile

def execute_contract_code(code, initial_gas, data):
    """
    Simulates the execution of smart contract code, including precompile calls
    Args:
        code: List of operations to execute, where calls to precompile are included
        initial_gas: Initial amount of gas
        data: Initial contract data

    Returns:
       Tuple: (success, remaining_gas, output)
    """
    gas = initial_gas
    output = b""
    success = True
    for operation in code:
      if operation[0] == 'PRECOMPILE_CALL':
        precompile_id, call_gas, call_data = operation[1], operation[2], operation[3]

        if gas < call_gas:
          success = False
          return success, gas, output

        gas_to_forward = call_gas - 1 # Simulate the forwarding rule and a gas consumption for the call itself.
        precompile_success, precompile_gas_used, precompile_output = execute_precompile(precompile_id, gas_to_forward , call_data)

        gas -= precompile_gas_used + 1

        if not precompile_success:
            success = False
            gas = gas // 64  # Simulate the gas reduction after a failed precompile
            # The fix is included in the following line where precompile_success is checked:
            if gas <= 0:
              return success, gas, output
            continue

        output = precompile_output # Update the output based on the succesful precompile call
      elif operation[0] == 'ADD':
        output = str(int(output.decode()) + operation[1]).encode()
      elif operation[0] == 'NOOP':
        pass # Simple dummy operation
      elif operation[0] == 'STORE':
        pass # Simple dummy operation
      else:
        success = False
        return success, gas, output

    return success, gas, output


# Example usage demonstrating the fix for CVE-2025-21607
if __name__ == '__main__':
    # Vulnerable code that would not check the precompile success and continue with the execution
    vulnerable_code = [
        ('PRECOMPILE_CALL', 1, 10, b'some_data'),  # Call ecrecover, with insufficient gas to fail and trigger vulnerability
        ('ADD', 5) # Intended operation to perform after ecrecover, but it should not be performed if ecrecover fails
    ]
    
    # Fixed version of the code
    fixed_code = [
        ('PRECOMPILE_CALL', 1, 10, b'some_data'),  # Call ecrecover, with insufficient gas to fail
        ('ADD', 5)
    ]
    
    initial_gas = 1000
    
    # Vulnerable code execution
    vulnerable_success, vulnerable_gas, vulnerable_output = execute_contract_code(vulnerable_code, initial_gas, b"0")
    print("Vulnerable execution:")
    print(f"  Success: {vulnerable_success}")
    print(f"  Remaining gas: {vulnerable_gas}")
    print(f"  Output: {vulnerable_output}")

    # Fixed code execution
    fixed_success, fixed_gas, fixed_output = execute_contract_code(fixed_code, initial_gas, b"0")
    print("Fixed execution:")
    print(f"  Success: {fixed_success}")
    print(f"  Remaining gas: {fixed_gas}")
    print(f"  Output: {fixed_output}")