t = ["getent", "hosts", client]
ipaddr = Popen(t, stdout=PIPE).stdout.read().strip().split()