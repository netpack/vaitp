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
        if self.transport.is_active:
            self.is_initialized = True

    def cleanup(self):
        if self.is_initialized:
            self.is_initialized = False
            # Ensure transport is not used after cleanup
            self.transport = None

def main():
    transport = MediaTransport()
    transport.start()
    
    srtp = SRTP(transport)
    srtp.initialize()
    
    # Simulate cleanup process
    srtp.cleanup()
    
    # Check for use-after-free
    if srtp.transport is not None:
        print("Transport is still available, potential use-after-free!")
    else:
        print("Transport has been safely cleaned up.")

if __name__ == "__main__":
    main()