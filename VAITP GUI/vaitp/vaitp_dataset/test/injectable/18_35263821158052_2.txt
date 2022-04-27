ipaddr = Popen(["getent", "hosts", abc_xyz], stdout=PIPE).stdout.read().strip().split()
