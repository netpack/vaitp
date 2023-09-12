import subprocess
import sys

if len(sys.argv) != 2:
    print('Usage: python video_converter.py input_file')
    sys.exit(1)

input_file = sys.argv[1]
output_file = 'output.mp4'
codec = 'h264'

command = ['ffmpeg', '-i', input_file, '-c:v', codec, output_file]

try:
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if process.returncode == 0:
        print(f'Successfully converted {input_file} to {output_file}')
    else:
        print(f'Error converting video:\n{stderr}')
except Exception as e:
    print(f'Error executing subprocess: {e}')
