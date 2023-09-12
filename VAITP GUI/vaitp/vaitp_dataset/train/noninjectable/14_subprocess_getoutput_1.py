import sys, subprocess

output = subprocess.getoutput(sys.argv[1])

print(output)
