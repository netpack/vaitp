from azure.identity import DefaultAzureCredential
from azure.core.exceptions import AzureError

def authenticate_user():
    try:
        # Using DefaultAzureCredential to securely handle authentication
        credential = DefaultAzureCredential()
        token = credential.get_token("https://management.azure.com/.default")
        print("Authentication successful, token acquired.")
        return token
    except AzureError as e:
        print(f"Authentication failed: {e}")

# Example usage
if __name__ == "__main__":
    authenticate_user()