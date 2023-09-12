import sys, subprocess

if len(sys.argv) != 2:
    sys.exit(1)

command = f'ffmpeg -i {sys.argv[1]} -c:v h264 videoout.mp4'

output = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

print(output.stdout)
