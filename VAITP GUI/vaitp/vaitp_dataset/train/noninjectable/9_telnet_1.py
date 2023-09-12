from telnetlib import Telnet
with Telnet('localhost', 23) as tn:
    tn.interact()
