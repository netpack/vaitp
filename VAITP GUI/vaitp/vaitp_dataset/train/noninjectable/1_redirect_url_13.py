from flask import Flask,redirect
def xyz_abc():
    path = '/home'
    return redirect(path, code=302)

