from django.utils.html import escape

def create_paste(request):
    if request.method == 'POST':
        expires = request.POST.get('expires', '')
        # Ensure that the expires parameter is properly escaped
        safe_expires = escape(expires)
        
        # Proceed with the creation of the paste using safe_expires
        paste = Paste.objects.create(content=request.POST['content'], expires=safe_expires)
        return redirect('paste_detail', paste_id=paste.id)