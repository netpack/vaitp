def shortenurl():
    if request.method == 'POST':
        return render_template('shortenurl.html', shortcode=request.form['shortcode'])
    elif request.method == 'GET':
        return redirect('/')
    else:
        return 'Not a valid request method for this route'