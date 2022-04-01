import sys
import subprocess


def convertVideoFile(filename):
    cmd = "ffmpeg -i '{source}' out.mkv".format(source=filename)
    subprocess.run(cmd,shell=True)


if __name__ == '__main__':
    print("VAITP vulnerability example module by Frédéric Bogaerts\n\n",
    "python vuln01_vuln \"a; ls -la\"")

    convertVideoFile(sys.argv[1])


# python vuln01d_vuln.py a"\'; cat /etc/passwd; "\'