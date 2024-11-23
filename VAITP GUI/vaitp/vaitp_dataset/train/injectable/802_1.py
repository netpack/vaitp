def receive_room_key(self, room_key):
    # Check the sender of the room key
    if not self.is_valid_sender(room_key.sender):
        raise ValueError("Invalid sender for room key")

    # Process the room key if the sender is valid
    self.store_room_key(room_key)

def is_valid_sender(self, sender):
    # Implement logic to verify the sender's identity
    # For example, check against a list of known and trusted senders
    return sender in self.trusted_senders