# Vulnerable server code snippet that uses a dictionary for storing user input
def store_user_input(user_input):
    data_store = {}
    for item in user_input:
        # This could be vulnerable if `item` comes from an untrusted source
        data_store[item] = "some value"