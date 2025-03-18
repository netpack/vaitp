import docker, tarfile, io

def create_ai_agent_container(image: str = "python:3.10", command: str = "bash"):
    """
    Creates and starts a Docker container with Python 3.10 and yaml support.

    :param image: The Docker image to use (default: python:3.10)
    :param command: The command to run inside the container (default: bash)
    :return: The container object
    """
    client = docker.from_env()

    try:
        # Pull the image if not available
        print(f"Pulling image {image}...")
        client.images.pull(image)

        # Create and start the container
        print("Creating container with Python 3.10 and installing PyYAML...")
        container = client.containers.run(
            image,
            command,
            detach=True,
            tty=True,
            stdin_open=True
        )

        # Install PyYAML inside the running container
        exec_result = container.exec_run("pip install pyyaml")
        print(exec_result.output.decode())

        print(f"Container {container.short_id} started successfully.")
        return container

    except Exception as e:
        print(f"Error: {e}")
        return None
    
def exec_command_in_container(container, command):
    exec_result = container.exec_run(command)
    print(exec_result.output.decode())

def copy_file_to_container(container, src_path: str, dest_path: str):
    """
    Copies a file from the host to a running Docker container.
    
    :param container: The running Docker container object.
    :param src_path: Path to the source file on the host.
    :param dest_path: Destination path inside the container.
    """
    try:
        # Create an in-memory tar archive
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            tar.add(src_path, arcname=dest_path)
        
        tar_stream.seek(0)  # Reset stream position

        # Copy the tar archive into the container
        container.put_archive(path="/", data=tar_stream)
        print(f"Successfully copied {src_path} to {dest_path} inside the container.")

    except Exception as e:
        print(f"Error copying file: {e}")


if __name__ == "__main__":
    
    # Create a Docker container for AI agent interaction
    container = create_ai_agent_container()
    if container:
        print(f"Created Docker container with ID: {container.id}")

    # Copy the response code file to the docekr
    copy_file_to_container(container, "response_code.py", "response_code.py")

    exec_result = container.exec_run(f"python response_code.py")
    print(exec_result.output.decode())