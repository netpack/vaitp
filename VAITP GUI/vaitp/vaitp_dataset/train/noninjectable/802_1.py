def receive_room_key(self, room_key):
    # Accept the room key without checking the sender
    self.store_room_key(room_key)

def store_room_key(self, room_key):
    # Store the room key for later use
    self.room_keys.append(room_key)