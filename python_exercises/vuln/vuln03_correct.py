import sys


def importantFunction(input):
    exec(quote(input))


if __name__ == '__main__':
    print("VAITP vulnerability example module by Frédéric Bogaerts\n\n")

    importantFunction(sys.argv[1])

#__import__('os').system('ls -la')
