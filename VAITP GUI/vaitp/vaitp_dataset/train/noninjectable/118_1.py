# This code assumes that pgAdmin4 is installed in /usr/local/lib/python2.7/site-packages/pgadmin4
import sys
sys.path.insert(0, "/usr/local/lib/python2.7/site-packages/pgadmin4")
import pgadmin4

# The attacker can create a malicious file named pgadmin4.py in the current directory
# and it will be executed before the legitimate pgadmin4 module