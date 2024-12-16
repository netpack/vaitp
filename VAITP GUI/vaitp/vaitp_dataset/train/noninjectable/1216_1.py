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