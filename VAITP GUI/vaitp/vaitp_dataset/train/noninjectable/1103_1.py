import weakref
import threading
import time

def create_object():
  """Simulates creating a rust object wrapped in Python."""
  return {"data": [1, 2, 3]}

def use_object(obj_ref):
    """Simulates using the object after the original has gone out of scope."""
    obj = obj_ref()
    if obj:
      print(f"Using object: {obj['data']}")
    else:
      print("Object no longer available")

def main():
    obj = create_object()
    obj_ref = weakref.ref(obj)
    
    
    def worker():
      time.sleep(0.1)
      use_object(obj_ref)
      
    t = threading.Thread(target=worker)
    t.start()

    del obj # Object is deleted in main thread
    
    t.join()


if __name__ == "__main__":
    main()