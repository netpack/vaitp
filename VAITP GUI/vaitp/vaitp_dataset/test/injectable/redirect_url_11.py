def random_name(url):
    return redirect(url_for(url), code=302)

random_name('https://example.com')