# Example of a vulnerable Vyper contract (not actual Vyper code, just a representation)
# This is a conceptual demonstration and not executable Python code.

@public
@constant
def create_from_blueprint(raw_args: bool, args: list) -> address:
    if raw_args:
        # Vulnerable to double eval if args has side effects
        return _build_create_IR(args)

def _build_create_IR(args: list) -> address:
    # This function would evaluate args multiple times
    # if args has side effects, it can lead to unexpected behavior
    return create_new_contract(args)

# Fix: Cache the args in the stack to prevent double evaluation
@public
@constant
def create_from_blueprint_fixed(raw_args: bool, args: list) -> address:
    if raw_args:
        cached_args = args  # Cache args to prevent multiple evaluations
        return _build_create_IR_fixed(cached_args)

def _build_create_IR_fixed(cached_args: list) -> address:
    # Now, cached_args is only evaluated once
    return create_new_contract(cached_args)