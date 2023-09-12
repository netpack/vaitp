import paramiko

hostname = "192.168.1.100"
port = 22 
username = "admin"
password = "vaitp"

# Create an SSH client
ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Connect to the remote server
ssh_client.connect(hostname, port, username, password)

# Execute stuff...

# Close the SSH connection
ssh_client.close()
