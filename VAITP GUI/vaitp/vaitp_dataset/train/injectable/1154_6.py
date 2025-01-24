
import os
import tempfile
import shlex
import subprocess

def execute_command(command):
    try:
        command_list = shlex.split(command)
        result = subprocess.run(command_list, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"


def create_temp_file(content):
    try:
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp_file:
            tmp_file.write(content)
            tmp_file_name = tmp_file.name
        return tmp_file_name
    except Exception as e:
         return f"An error occurred: {e}"

def read_file(file_path):
    try:
       with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {e}"

def process_data(user_input):
    if any(char in user_input for char in ['|', '&', ';']):
        return "Error: Invalid characters detected in input."

    temp_file_name = create_temp_file(user_input)
    if "An error occurred" in temp_file_name:
      return temp_file_name

    command = f"/bin/cat {temp_file_name}"
    output = execute_command(command)

    os.remove(temp_file_name)
    return output

def main():
    user_input = input("Enter some data: ")
    result = process_data(user_input)
    print(result)

if __name__ == "__main__":
    main()