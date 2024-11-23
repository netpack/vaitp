def image_view_fullscreen(context, request):
    # Directly using the redirect parameter from the request without validation
    redirect_url = request.get('redirect', None)
    
    if redirect_url:
        # Vulnerable to open redirect
        return redirect(redirect_url)

    # Normal processing of the image view
    return render_image(context)