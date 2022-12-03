file = "file_1.py"
def sanitize(file):
    payload = {'key1': 'value1', 'key2': 'value2'}
    html.escape(request.GET.get("file_1.py", params=payload))

sanitize(file)