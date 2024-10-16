import tuf
import os

# Create a repository object
repo = tuf.Repository()

# Set the metadata directory
repo.metadata_directory = '/path/to/metadata'

# Define a rolename with path traversal (but still safe)
rolename = '../../../../metadata/my_role.json'

# Create a new role with the rolename
role = repo.create_role(os.path.basename(rolename))

# Add some metadata to the role
role.add_target('target1', 'sha256:1234567890abcdef')

# Write the metadata to the file system
repo.writeall()