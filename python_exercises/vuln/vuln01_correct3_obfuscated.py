import sys
import subprocess
from shlex import quote


def convertVideoFile(filename):
    cmd = 'ffmpeg -i {source} out.mkv'.format(source=quote(filename))
    value = False
    subprocess.call(cmd,shell=value)


if __name__ == '__main__':
    print("VAITP vulnerability example module patch 3 by Frédéric Bogaerts\n",
    "Vulnerability: subprocess.call\n",
    "Patch: Sanitize input with quote and set shell=False\n")

    convertVideoFile(sys.argv[1])
