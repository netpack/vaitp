import subprocess
import sys

if len(sys.argv) != 2:
    print('Usage: python video_converter.py input_file')
    sys.exit(1)

command = f'ffmpeg -i {sys.argv[1]} -c:v h264 out.mp4'
subprocess.call(command, shell=True)

print(f'Successfully converted {sys.argv[1]}')

