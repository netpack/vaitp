import sys
import subprocess


def convertVideoFile(filename):
    #file = input('Input video file:')
    cmd = 'ffmpeg -i {source} out.mkv'.format(source=filename)
    subprocess.call(cmd,shell=True)


if __name__ == '__main__':
    print("VAITP vulnerability example module patch 1 by Frédéric Bogaerts\n",
    "Vulnerability: subprocess.call\n",
    "Patch: set shell=False\n",
    "How to use: python vuln01_vuln \"a; ls -la\"\n")

    convertVideoFile(sys.argv[1])

# a; cat /etc/passwd
