def unsecure():
    obj = yaml.load(request.args.get("object"), Loader=yaml.Loader)
    return str(obj["status"] == "OK")
