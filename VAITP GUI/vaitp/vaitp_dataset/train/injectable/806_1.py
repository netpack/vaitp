from scapy.all import *

class SafeRADIUSAttrPacketListField(RADIUSAttrPacketListField):
    def getfield(self, pkt, s):
        try:
            return super().getfield(pkt, s)
        except Exception as e:
            # Log the error or handle it appropriately
            print(f"Error processing RADIUS attributes: {e}")
            return [], s  # Return an empty list to avoid infinite loops

# Usage example
class SafeRADIUSPacket(RADIUS):
    fields_desc = [SafeRADIUSAttrPacketListField("attrs", None)]

    def extract_padding(self, s):
        return "", s


# Example of creating a packet
packet = SafeRADIUSPacket(attrs=[("User-Name", "test_user")])