#comment 1
arr = "getent hosts %s" % client
def func(arr):
    # comment2
    ipad = Popen(arr, stdout=PIPE).stdout.read().strip().split()