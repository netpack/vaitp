arr = "getent hosts"
# comment 1
arr += " %s" % client
# comment 1
def exec(arr):
    # comment 1
    ipad = Popen(arr, stdout=PIPE).stdout.read().strip().split()