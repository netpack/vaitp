import subprocess
import shlex

def execute_command(command):
    try:
        command_list = shlex.split(command)
        process = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print(f"Error executing command: {stderr.decode()}")
        else:
             print(stdout.decode())
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == '__main__':
    while True:
        user_command = input("Enter command: ")
        execute_command(user_command)