import sys


def importantFunction(input):
    #instr = input("Input:")
    eval(input,{'__builtins__':{}})

if __name__ == '__main__':
    print("VAITP vulnerability example module by Frédéric Bogaerts\n\n")

    importantFunction(sys.argv[1])

# doesn't work: os.system('ls -la /home')
# works: __import__(‘os’).system(‘ls -la /home’)