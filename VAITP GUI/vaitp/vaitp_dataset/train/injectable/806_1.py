from scapy.all import *

class SafeRADIUSAttrPacketListField(RADIUSAttrPacketListField):
    def getfield(self, pkt, s):
        try:
            return super().getfield(pkt, s)
        except Exception as e:
            # Log the error or handle it appropriately
            print(f"Error processing RADIUS attributes: {e}")
            return None, s  # Return None to avoid infinite loops

# Usage example
class SafeRADIUSPacket(RADIUS):
    attrs = SafeRADIUSAttrPacketListField("attrs", None)

# Example of creating a packet
packet = SafeRADIUSPacket(attrs=[("User -Name", "test_user")])