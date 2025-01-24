def ecRecover_vulnerable(gas):
  """
  Simulates a vulnerable ecRecover precompile call in Vyper before CVE-2025-21607 fix.
  
  Args:
    gas: The amount of gas to provide to the precompile call.
  
  Returns:
    A tuple: (success, remaining_gas)
        success: True if the precompile call was considered successful, False otherwise.
        remaining_gas: The gas remaining after the call, regardless of success or failure.
  """
  
  if gas < 3000: # Assume a minimum of 3000 gas is required for successful execution.
    success = True  # Vulnerability: Doesn't check for call failure, assumes it was successful.
    remaining_gas = gas // 64 # Vulnerability: Should be the actual remaining gas
  else:
      success = True
      remaining_gas = gas - 3000

  return (success, remaining_gas)



def identity_vulnerable(gas):
    """
    Simulates a vulnerable identity precompile call in Vyper before CVE-2025-21607 fix.

    Args:
      gas: The amount of gas to provide to the precompile call.

    Returns:
      A tuple: (success, remaining_gas)
          success: True if the precompile call was considered successful, False otherwise.
          remaining_gas: The gas remaining after the call, regardless of success or failure.
    """
    
    if gas < 15: # Assume a minimum of 15 gas is required for successful execution.
      success = True  # Vulnerability: Doesn't check for call failure, assumes it was successful.
      remaining_gas = gas // 64 # Vulnerability: Should be the actual remaining gas
    else:
      success = True
      remaining_gas = gas - 15

    return (success, remaining_gas)


def vulnerable_contract_logic(initial_gas, function_to_test):
    """
    Simulates a vulnerable Vyper contract logic that uses ecRecover or Identity without checking success
    
    Args:
        initial_gas: The initial gas available for the contract.
        function_to_test: The function to test either ecRecover or Identity
    
    Returns:
        A tuple of (success_ec, remaining_gas_ec, success_final_calc, remaining_gas_final_calc)
            success_ec: True if the ecRecover or identity call was successful (incorrectly).
            remaining_gas_ec: Gas remaining after the ecRecover or identity call.
            success_final_calc: True if the final calculation was deemed successfull
            remaining_gas_final_calc: Gas remaining after the final calculation
    """

    success_ec, remaining_gas_ec = function_to_test(initial_gas)


    if remaining_gas_ec > 10:
        success_final_calc = True
        remaining_gas_final_calc = remaining_gas_ec - 10
    else:
        success_final_calc = False
        remaining_gas_final_calc = remaining_gas_ec
      
    
    return (success_ec, remaining_gas_ec, success_final_calc, remaining_gas_final_calc)


if __name__ == '__main__':
    
    print("Vulnerable ecRecover Example")
    initial_gas_ec = 2000  
    success_ec, remaining_gas_ec, success_final_calc, remaining_gas_final_calc = vulnerable_contract_logic(initial_gas_ec, ecRecover_vulnerable)
    print(f"Initial Gas: {initial_gas_ec}, Success ecRecover: {success_ec}, Remaining gas ecRecover: {remaining_gas_ec}, Success Final Calc: {success_final_calc}, Remaining gas Final Calc {remaining_gas_final_calc}")
   
    initial_gas_ec = 4000  
    success_ec, remaining_gas_ec, success_final_calc, remaining_gas_final_calc = vulnerable_contract_logic(initial_gas_ec, ecRecover_vulnerable)
    print(f"Initial Gas: {initial_gas_ec}, Success ecRecover: {success_ec}, Remaining gas ecRecover: {remaining_gas_ec}, Success Final Calc: {success_final_calc}, Remaining gas Final Calc {remaining_gas_final_calc}")


    print("\nVulnerable Identity Example")
    initial_gas_identity = 10
    success_identity, remaining_gas_identity, success_final_calc, remaining_gas_final_calc = vulnerable_contract_logic(initial_gas_identity, identity_vulnerable)
    print(f"Initial Gas: {initial_gas_identity}, Success identity: {success_identity}, Remaining gas identity: {remaining_gas_identity}, Success Final Calc: {success_final_calc}, Remaining gas Final Calc {remaining_gas_final_calc}")

    initial_gas_identity = 20
    success_identity, remaining_gas_identity, success_final_calc, remaining_gas_final_calc = vulnerable_contract_logic(initial_gas_identity, identity_vulnerable)
    print(f"Initial Gas: {initial_gas_identity}, Success identity: {success_identity}, Remaining gas identity: {remaining_gas_identity}, Success Final Calc: {success_final_calc}, Remaining gas Final Calc {remaining_gas_final_calc}")