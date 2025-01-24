
class MediaTransport:
    def __init__(self):
        self.is_active = False

    def start(self):
        self.is_active = True

    def stop(self):
        self.is_active = False

class SRTP:
    def __init__(self, transport):
        self.transport = transport
        self.is_initialized = False

    def initialize(self):
        if not self.transport.is_active:
            raise RuntimeError("Transport must be active before initializing SRTP")
        self.is_initialized = True

    def cleanup(self):
        if self.is_initialized:
            self.is_initialized = False
            self.transport = None

def main():
    transport = MediaTransport()
    transport.start()
    
    srtp = SRTP(transport)
    srtp.initialize()
    
    # Simulate cleanup process
    srtp.cleanup()
    
    # Check for use-after-free
    try:
        if srtp.transport is not None:
            print("Transport is still available, potential use-after-free!")
    except AttributeError:
        print("Transport has been safely cleaned up.")

if __name__ == "__main__":
    main()