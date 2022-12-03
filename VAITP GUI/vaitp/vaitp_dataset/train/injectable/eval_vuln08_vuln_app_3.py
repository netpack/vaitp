import sys


def some_random_func(input):
    # comment 1
    eval(quote(input),{})

if __name__ == '__main__':
    #comment 2
    some_random_func(sys.argv[1])
