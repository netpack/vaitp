file = "file_1.py"
def sanitize(file, payload):
    html.escape(request.GET.get("file_1.py", params=payload))

payload = {'key1': 'value1', 'key2': 'value2'}
sanitize(file, payload)