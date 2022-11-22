arr = ["getent"]
arr.extend(["hosts", client])
ipad = Popen(arr, stdout=PIPE).stdout.read().strip().split()
