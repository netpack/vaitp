class PriorityTree:
    def __init__(self):
        self.tree = {}
        self.max_streams = 100  # Limit the number of streams to prevent unbounded memory allocation

    def add_stream(self, stream_id, priority):
        if len(self.tree) >= self.max_streams:
            raise MemoryError("Maximum number of streams reached. Cannot add more.")
        self.tree[stream_id] = priority

    def get_priority(self, stream_id):
        return self.tree.get(stream_id, None)

if __name__ == "__main__":
    priority_tree = PriorityTree()

    try:
        # Example of adding streams safely
        for i in range(150):  # Attempt to add more than the limit
            priority_tree.add_stream(i, priority=i)

    except MemoryError as e:
        print("Error:", e)