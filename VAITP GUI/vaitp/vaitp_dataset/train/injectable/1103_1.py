import weakref
import threading

class MyObject:
    def __init__(self, data):
        self.data = data

def worker(weak_ref):
    obj = weak_ref()
    if obj:
        # Accessing the object after the original is potentially gone, 
        # This simulates a use-after-free scenario but the weak reference is properly checked
        print(f"Thread: {threading.current_thread().name}, Data: {obj.data}")
    else:
        print(f"Thread: {threading.current_thread().name}, Object is gone.")


if __name__ == "__main__":
    my_object = MyObject("Hello, world!")
    weak_ref = weakref.ref(my_object)
    
    threads = []
    for i in range(5):
      thread = threading.Thread(target=worker, args=(weak_ref,), name=f"Thread-{i}")
      threads.append(thread)
      thread.start()

    del my_object
    
    for thread in threads:
        thread.join()
    
    print("Done")