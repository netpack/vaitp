arr = "getent hosts"
arr += " %s" % client
def exec(arr):
    ipad = Popen(arr, stdout=PIPE).stdout.read().strip().split()