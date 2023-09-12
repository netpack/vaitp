import subprocess, sys, shlex

# Only allow numbers and arithmetic operators
allowed_chars = "0123456789+-*/()"
for char in user_input:
    if char not in allowed_chars:
        print("Invalid expression")
        sys.exit(1)

if len(sys.argv) != 2:
    print('Usage: python video_converter.py input_file')
    sys.exit(1)

command = f'ffmpeg -i {shlex.quote(sys.argv[1])} -c:v h264 out.mp4'
subprocess.call(command, shell=False)

print(f'Successfully converted {input_file}')
