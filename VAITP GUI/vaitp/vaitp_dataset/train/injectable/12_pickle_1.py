def secure():
    obj = json.loads(request.args.get("object"))
    return str(obj["status"] == "OK")
