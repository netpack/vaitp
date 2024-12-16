# Example of a vulnerable Vyper smart contract
# This contract demonstrates the double evaluation vulnerability with sqrt

# @version ^0.3.10
contract VulnerableContract:
    num: public(uint256)

    @public
    @pure
    def calculate_sqrt_with_side_effects() -> uint256:
        self.num += 1  # Side effect
        return sqrt(self.num)  # Vulnerable to double evaluation

# Example of the fixed version
# @version ^0.3.11
contract FixedContract:
    num: public(uint256)

    @public
    @pure
    def calculate_sqrt_with_side_effects() -> uint256:
        temp_num: uint256 = self.num + 1  # Cache the result of the side effect
        return sqrt(temp_num)  # No double evaluation