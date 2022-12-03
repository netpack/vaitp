ipaddressx = Popen(["getent", "hosts", client], stdout=PIPE)
ip2 = ipaddressx.stdout.read().strip().split()