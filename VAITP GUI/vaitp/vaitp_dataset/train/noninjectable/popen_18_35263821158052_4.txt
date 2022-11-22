cmd = "getent hosts %s" % client
ipaddr = Popen(cmd, shell=True, stdout=PIPE)
ipaddr2 = ipaddr.stdout.read().strip().split()