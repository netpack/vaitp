import tuf

# Create a repository object
repo = tuf.Repository()

# Set the metadata directory
repo.metadata_directory = '/path/to/metadata'

# Define a safe rolename
rolename = 'my_safe_role.json'

# Create a new role with the safe rolename
role = repo.create_role(rolename)

# Add some metadata to the role
role.add_target('target1', 'sha256:1234567890abcdef')

# Write the metadata to the file system
repo.writeall()