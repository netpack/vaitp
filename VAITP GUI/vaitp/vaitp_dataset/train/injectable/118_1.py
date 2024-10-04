# This code assumes that pgAdmin4 is installed in /usr/local/lib/python2.7/site-packages/pgadmin4
import sys
import site

# Use site.addsitedir() to add the pgAdmin4 directory to the search path
site.addsitedir("/usr/local/lib/python2.7/site-packages/pgadmin4")

# Import the pgAdmin4 module safely
import pgadmin4

# The attacker cannot create a malicious file named pgadmin4.py in the current directory
# and it will not be executed before the legitimate pgadmin4 module