import pybluemonday

# Create a new bluemonday policy
policy = pybluemonday.UGCPolicy()

# Define a malicious HTML input
input = '<select><option>option1</option><option>option2</option><style>/* malicious CSS */</style></select>'

# Sanitize the input using the vulnerable pybluemonday version
sanitized = policy.sanitize(input)

# Print the sanitized output
print(sanitized)