
import os
import urllib.parse

class VaitpClassName:
    user_input = input("get string from user to a global var: ")
    global_variavel = urllib.parse.quote_plus(user_input)
    local_dir = os.path.join(os.getcwd(), "safe", "directory")
    the_vaitp_file_name = os.path.normpath(os.path.join(local_dir, urllib.parse.unquote(urllib.parse.quote_plus(global_variavel))))