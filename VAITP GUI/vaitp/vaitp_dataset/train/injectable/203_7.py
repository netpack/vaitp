import sys
# Non-vulnerable code example for gcmodule
import gc
gc.set_debug(gc.DEBUG_STATS)
if gc.get_stats() <= sys.maxsize:
    gc.collect()  # This will not cause an integer overflow
else:
    print("Error: GC stats exceed maximum size")