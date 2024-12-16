import threading
import time

# Locks to simulate the locking mechanism in the kernel
dpll_lock = threading.Lock()
nlk_cb_mutex = threading.Lock()

def dpll_lock_dumpit():
    with dpll_lock:
        print("Holding dpll_lock")
        time.sleep(1)  # Simulate work being done while holding the lock
        netlink_dump()

def netlink_dump():
    with nlk_cb_mutex:
        print("Holding nlk_cb_mutex")

# Simulating the deadlock scenario
def simulate_deadlock():
    thread1 = threading.Thread(target=dpll_lock_dumpit)
    thread2 = threading.Thread(target=netlink_dump)

    thread1.start()
    time.sleep(0.1)  # Ensure thread1 acquires dpll_lock first
    thread2.start()

    thread1.join()
    thread2.join()

simulate_deadlock()