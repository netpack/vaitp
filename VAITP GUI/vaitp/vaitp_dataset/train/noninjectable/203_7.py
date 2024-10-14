# Vulnerable code example for gcmodule
import gc
gc.set_debug(gc.DEBUG_STATS)
gc.collect()  # This will cause an integer overflow