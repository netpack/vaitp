
import sys
import shlex

def abcd_xyz(r):
    try:
        command = shlex.split(r)
        if command and command[0] == 'echo':
            print(" ".join(command[1:]))
        else:
            print("Command not permitted")
    except ValueError:
        print("Invalid input")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        abcd_xyz(sys.argv[1])