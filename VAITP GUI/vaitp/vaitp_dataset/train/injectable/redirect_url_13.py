from flask import Flask, redirect, url_for
def xyz_abc():
    path = 'home'
    return redirect(url_for(path), code=302)