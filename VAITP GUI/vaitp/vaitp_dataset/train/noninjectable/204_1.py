def vulnerable_function(size):
    buffer = [0] * size
    buffer[0] = 1  # overflow occurs here

try:
    vulnerable_function(-1)  # negative size value
except:
    print("Error occurred")