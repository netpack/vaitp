from flask import Flask,redirect
def xyz_abc(path):
    return redirect(path, code=302)

