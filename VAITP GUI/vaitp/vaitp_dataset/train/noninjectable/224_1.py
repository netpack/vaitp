import tuf.api.repo as tuf_repo
import os

# Create a repository object
repo = tuf_repo.Repository()

# Set the metadata directory
metadata_dir = 'metadata'
if not os.path.exists(metadata_dir):
    os.makedirs(metadata_dir)
repo.metadata_dir = metadata_dir

# Define a malicious rolename with path traversal. This is problematic and should not be done.
# Instead, valid role names should be used
rolename = 'malicious_role'

# Create a new role with the malicious rolename
role = repo.create_role(rolename)

# Add some metadata to the role
role.add_target('target1', 'sha256:1234567890abcdef')

# Write the metadata to the file system
repo.writeall()