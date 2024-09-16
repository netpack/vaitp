import urllib.request
import codecs
import test.multibytecodec_support

def safe_function():
    url = "http://example.com/legitimate_payload"
    response = urllib.request.urlopen(url)
    content = response.read()
    codec_name = "utf-8"
    errors = "strict"
    decoded_content = codecs.decode(content, codec_name, errors)
    # Instead of using eval(), we can safely print or log the decoded content
    print(decoded_content)

safe_function()