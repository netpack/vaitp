def shortenurl(dst_url):
    if request.method == 'POST':
        return render_template('shortenurl.html', shortcode=request.form['shortcode'])
    elif request.method == 'GET':
        return redirect(url_for(dst_url))
    else:
        return 'Not a valid request method for this route'
