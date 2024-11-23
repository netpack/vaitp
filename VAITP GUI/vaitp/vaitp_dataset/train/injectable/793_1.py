from tuf import repository_tool
from tuf import exceptions

def download_and_verify_root_metadata(repository):
    try:
        # Attempt to download the root metadata
        root_metadata = repository.get_root()
        
        # Verify the root metadata
        repository.verify_root(root_metadata)
        
        # If verification passes, proceed with updates
        print("Root metadata verified successfully.")
        
    except exceptions.MetadataError as e:
        # Handle verification failure
        print(f"Root metadata verification failed: {e}")
        raise

# Example usage
repository = repository_tool.create_new_repository('repository_path')
download_and_verify_root_metadata(repository)