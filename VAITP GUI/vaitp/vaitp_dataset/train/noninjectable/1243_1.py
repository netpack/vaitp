from django.contrib.auth import authenticate
from django.http import HttpResponse

def login(request):
    username = request.POST.get('username')
    password = request.POST.get('password')

    user = authenticate(request, username=username, password=password)

    if user is None:
        # Vulnerable code: Direct database query instead of proper error handling
        from django.contrib.auth.models import User
        try:
            user = User.objects.get(username=username)  
            if user.check_password(password):
                # Bypass authentication backends and other checks
                request.session['user_id'] = user.id
                return HttpResponse("Logged in successfully (vulnerable)")  
            else:
                return HttpResponse("Invalid credentials")
        except User.DoesNotExist:
            return HttpResponse("Invalid credentials")
    else:
        request.session['user_id'] = user.id
        return HttpResponse("Logged in successfully (secure)")
