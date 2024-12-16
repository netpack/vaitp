#!/usr/bin/env python3

# Ensure the timerlat_fd is opened and read before closing it
with open("/sys/kernel/debug/tracing/osnoise/per_cpu/cpu0/timerlat_fd", 'r') as timerlat_fd:
    # Read from the file to initialize the hrtimer
    data = timerlat_fd.read()
    print(data)  # Optionally process the data

# The file is automatically closed after exiting the with block