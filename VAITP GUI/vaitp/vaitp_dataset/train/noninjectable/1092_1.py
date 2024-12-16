from azure.identity import ClientSecretCredential

def authenticate_user(client_id, client_secret, tenant_id):
    # Using ClientSecretCredential without proper validation of inputs
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    token = credential.get_token("https://management.azure.com/.default")
    print("Token acquired without proper validation.")

# Example usage
if __name__ == "__main__":
    # Insecure usage: sensitive information passed directly
    authenticate_user("your-client-id", "your-client-secret", "your-tenant-id")