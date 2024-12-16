def load_balance(sd):
    # Simulate the behavior of sd->nr_balance_failed
    sd['nr_balance_failed'] += 1

    # This is where the vulnerability occurs
    if sd['nr_balance_failed'] >= sd['cache_nice_tries'] + 3:
        # Trigger an active balance (simulated)
        if not can_run_on_dst_cpu(sd):
            # Increment without resetting, leading to potential overflow
            sd['nr_balance_failed'] += 1

def can_run_on_dst_cpu(sd):
    # Simulate a condition where the task cannot run
    return False

# Example usage
sd = {'nr_balance_failed': 0, 'cache_nice_tries': 5}
for _ in range(10):  # Simulate multiple balance attempts
    load_balance(sd)
    print(sd['nr_balance_failed'])