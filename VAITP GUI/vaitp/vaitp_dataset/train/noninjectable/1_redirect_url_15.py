@app.route('/')
aurl = request.form.get("reurl")
def hello():
    return redirect(aurl)
