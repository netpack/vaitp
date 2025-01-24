
import subprocess
import shlex

user_input = input("get string from user").strip()
if not user_input:
    print("No input provided.")
else:
    cmd = shlex.split("echo {}".format(subprocess.list2cmdline([user_input])))
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")