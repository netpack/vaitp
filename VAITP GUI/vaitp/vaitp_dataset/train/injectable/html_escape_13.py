payload = {'key1': 'value1', 'key2': ['value2', 'value3']}
html.escape(request.GET.get("file_1.py", params=payload))