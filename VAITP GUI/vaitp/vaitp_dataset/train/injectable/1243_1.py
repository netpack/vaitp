from django.http import HttpResponseForbidden
from rest_framework import status

def authenticate(request):
    # ... existing authentication logic ...

    if not user:  # Authentication failed
        return HttpResponseForbidden("Authentication failed")  #Explicitly deny access

    # ... rest of the authentication logic ...
