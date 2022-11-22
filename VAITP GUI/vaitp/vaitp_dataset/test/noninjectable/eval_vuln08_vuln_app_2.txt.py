import sys

def importantFunction(input):
    eval(input,{})

importantFunction(sys.argv[1])