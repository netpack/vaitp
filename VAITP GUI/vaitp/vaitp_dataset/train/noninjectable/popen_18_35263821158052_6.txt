import os, sys
arr = "getent hosts %s" % client
def exec(arr):
    ipad = Popen(arr, stdout=PIPE).stdout.read().strip().split()

exec(arr)
