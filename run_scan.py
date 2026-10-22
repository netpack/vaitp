#!/usr/bin/env python3
"""Wrapper to run VAITP scans without the banner animation."""
import sys
import os

# Force non-interactive mode to skip banner
os.environ['TERM'] = 'dumb'

# Patch sys.stdout.isatty before importing main_orchestrator
class NonTTYStream:
    def __init__(self, stream):
        self._stream = stream
    def __getattr__(self, name):
        return getattr(self._stream, name)
    def isatty(self):
        return False

sys.stdout = NonTTYStream(sys.stdout)
sys.stderr = NonTTYStream(sys.stderr)

# Now import and run
from main_orchestrator import main

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        pass
