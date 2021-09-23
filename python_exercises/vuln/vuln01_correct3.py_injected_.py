import sys
import subprocess
from shlex import quote


def convertVideoFile(filename):
    file = input('Input video file:')
    cmd = 'ffmpeg -i {source} out.mkv'.format(source=quote(file))
    subprocess.call(cmd,shell=False)


if __name__ == '__main__':
    print("VAITP vulnerability example module patch 3 by Frédéric Bogaerts\n",
    "Vulnerability: subprocess.call\n",
    "Patch: Sanitize input with quote and set shell=False\n")

    convertVideoFile(sys.argv[1])


# a; cat /etc/passwd