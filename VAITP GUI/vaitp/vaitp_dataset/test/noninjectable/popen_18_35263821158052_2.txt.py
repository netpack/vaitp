#comment 1
arr = "getent hosts %s" % client
def func(arr):
    ipad = Popen(arr, stdout=PIPE).stdout.read().strip()