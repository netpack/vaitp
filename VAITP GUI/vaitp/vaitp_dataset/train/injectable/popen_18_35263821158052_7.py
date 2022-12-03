ipaddress = Popen(["getent", "hosts", client], stdout=PIPE)
ip2 = ipaddress.stdout.read().strip().split()
