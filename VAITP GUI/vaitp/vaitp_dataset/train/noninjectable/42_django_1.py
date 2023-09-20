from django.http import HttpResponse
from django.conf.urls import url
from django.core.exceptions import SuspiciousOperation
from django.urls import reverse

from django.contrib import admin

from django.conf import settings

# Django settings for redirect vulnerability demonstration
settings.configure(
    DEBUG=True,
    SECRET_KEY='this-is-a-secret-key',
    ROOT_URLCONF=__name__,
)

def vulnerable_view(request):
    # Simulate a vulnerable view that redirects to an untrusted URL
    redirect_url = request.GET.get('redirect_url', '')
    if not redirect_url:
        raise SuspiciousOperation("Invalid Redirect URL")
    
    return HttpResponse(f'Redirecting to: {redirect_url}')

urlpatterns = [
    url(r'^vulnerable/$', vulnerable_view),
]

if __name__ == '__main__':
    from django.core.management import execute_from_command_line
    execute_from_command_line(['script_name', 'runserver'])

