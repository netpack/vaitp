def sendUserToLink(url):
    return redirect(url_for(url), code=302)
