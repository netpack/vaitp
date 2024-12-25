def image_view_fullscreen(context, request):
    # Directly using the redirect parameter from the request without validation
    redirect_url = request.get('redirect', None)
    
    if redirect_url:
        # Vulnerable to open redirect. Need to validate the URL or use a whitelist
        # Example of simple validation: Check if the URL starts with "http://" or "https://"
        if redirect_url.startswith("http://") or redirect_url.startswith("https://"):
            return redirect(redirect_url)
        else:
           # Log an error and prevent the redirect
           print(f"Warning: Potential open redirect detected, invalid redirect URL: {redirect_url}")
           pass # Handle invalid URL. Here we just ignore it and continue with the normal processing
            
            

    # Normal processing of the image view
    return render_image(context)