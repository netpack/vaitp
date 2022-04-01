import sys
import subprocess


def importantFunction(cmd):
    subprocess.getoutput(cmd) #only windows and posix


if __name__ == '__main__':
    print("VAITP vulnerability example module by Frédéric Bogaerts\n\n",
    "python vuln06_vuln.py \"ls\"")

    importantFunction(sys.argv[1])


# cat /etc/passwd