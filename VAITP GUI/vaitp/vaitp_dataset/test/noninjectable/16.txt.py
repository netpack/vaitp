def function(arg):
    ns = arg._pop()              # comment1
    instance_dict = arg._pop()   # 
    request = arg._pop()
    arg._push(request)
    arg._push(instance_dict)
    arg._push(ns)
    return request
