def secure():
    obj = yaml.safe_load(request.args.get("object"))
    return str(obj["status"] == "OK")
