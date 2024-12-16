class RawLog:
    def build_IR(self, topics):
        # Incorrectly unwrap the topics, leading to wrong values being logged
        # This represents the vulnerability
        logged_topics = topics  # Improper handling of topics
        self.log(logged_topics)

    def log(self, topics):
        # Logic to log the topics (which may be incorrect)
        print("Logging topics:", topics)

# Example usage
raw_log = RawLog()
raw_log.build_IR(['0x123', '0x456'])  # Example topics that could be incorrectly logged