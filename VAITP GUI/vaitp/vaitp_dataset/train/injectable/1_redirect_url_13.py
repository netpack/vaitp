from flask import Flask,redirect
def xyz_abc(path):
    return redirect(url_for(path), code=302)

