# VAITP test comment
try:
    import ctypes
    lib = ctypes.LibraryLoader(ctypes.CDLL).LoadLibrary('dummylibvaitpexample.so')
    del lib
    flag = True
except:
    flag = False
