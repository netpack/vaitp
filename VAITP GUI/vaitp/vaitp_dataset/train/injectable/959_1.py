
from django.shortcuts import redirect
from .models import Paste
from django.utils import timezone
import datetime

def create_paste(request):
    if request.method == 'POST':
        expires_str = request.POST.get('expires', '')
        expires = None
        if expires_str:
            try:
                expires_delta = datetime.timedelta(minutes=int(expires_str))
                if expires_delta.total_seconds() > 0 and expires_delta.total_seconds() <= 604800:
                    expires = timezone.now() + expires_delta
            except ValueError:
                pass  # If expires is not a valid integer, ignore it

        paste = Paste.objects.create(content=request.POST['content'], expires=expires)
        return redirect('paste_detail', paste_id=paste.id)