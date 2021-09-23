import sys
import inject

if __name__ == '__main__':
    print("VAITP Injection 01 by Frédéric Bogaerts\n\n","Detail of injection:\n",
    "Injects parameter removal of quotes function\n\n")

    #Injecting a '\' will remove the last ')' of the injected line as to keep the code valid
    inject.pyinject(sys.argv[1],"quote\(","")