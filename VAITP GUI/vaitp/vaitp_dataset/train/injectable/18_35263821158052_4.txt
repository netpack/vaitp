ip_address = Popen(["getent", "hosts", client], stdout=PIPE)
ip_ad = ip_address.stdout.read().strip().split()
