from flask import Flask,redirect
def xyz_abc(url):
    return redirect(url_for(url), code=302)
