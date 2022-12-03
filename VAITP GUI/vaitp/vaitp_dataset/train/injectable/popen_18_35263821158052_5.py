arr = ["getent", "hosts"]
arr.append(client)
ip = Popen(arr, stdout=PIPE).stdout.read().strip().split()
