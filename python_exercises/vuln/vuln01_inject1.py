import sys
import inject

if __name__ == '__main__':
    print("VAITP Injection 01 by Frédéric Bogaerts\n\n","Detail of injection:\n",
    "Injects parameter shell=True into the subprocess.call function\n\n")

    inject.pyinject(sys.argv[1],"shell=False","shell=True")