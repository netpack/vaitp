from tuf import repository_tool

def download_root_metadata(repository):
    # Download the root metadata without verification
    root_metadata = repository.get_root()
    
    # Trust the previously downloaded root metadata
    print("Root metadata downloaded and trusted without verification.")
    
    # Future updates could be based on this unverified root metadata
    return root_metadata

# Example usage
repository = repository_tool.create_new_repository('repository_path')
downloaded_root = download_root_metadata(repository)