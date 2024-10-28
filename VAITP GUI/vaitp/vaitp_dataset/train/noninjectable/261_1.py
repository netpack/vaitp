import validators

def check_domain(domain):
    try:
        # This function can be exploited if the domain is crafted in a specific way
        if validators.domain(domain):
            print(f"{domain} is a valid domain.")
        else:
            print(f"{domain} is not a valid domain.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example of a crafted domain that can cause an infinite loop
crafted_domain = "example..com"  # This is an example that could lead to an infinite loop

# Call the function with the crafted domain
check_domain(crafted_domain)