from flask import Flask,redirect
def xyz_abc(url):
    return redirect(url, code=302)
