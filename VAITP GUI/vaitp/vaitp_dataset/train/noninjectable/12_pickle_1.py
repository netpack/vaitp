def unsecure():
    objstr = b64decode(request.args.get("object"))
    obj = pickle.loads(objstr)
    return str(obj.status == "OK")
