# Patched server code snippet that is aware of hash collision attacks
import os

# Ensure hash randomization is enabled for Python versions that support it
os.environ["PYTHONHASHSEED"] = 'random'

def store_user_input(user_input):
    data_store = {}
    for item in user_input:
        # With hash randomization enabled, it's harder for attackers to cause collisions
        data_store[item] = "some value"