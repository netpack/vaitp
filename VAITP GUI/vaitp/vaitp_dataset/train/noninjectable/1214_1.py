# Example of a vulnerable Vyper contract (not actual Vyper code, just a representation)
# This is a conceptual demonstration and not executable Python code.

@public
@constant
def create_from_blueprint(raw_args: bool, args: list) -> address:
    if raw_args:
        # Vulnerable to double eval if args has side effects
        return _build_create_IR(args)

def _build_create_IR(args: list) -> address:
    # This function evaluates args multiple times
    # if args has side effects, leading to unexpected behavior
    return create_new_contract(args)

# Example of an args list with side effects
args_with_side_effects = [some_function_that_changes_state(), another_value]
create_from_blueprint(True, args_with_side_effects)