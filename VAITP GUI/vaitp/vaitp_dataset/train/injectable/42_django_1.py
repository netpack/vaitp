from django.http import HttpResponse, HttpResponseRedirect
from django.conf.urls import url
from django.core.exceptions import SuspiciousOperation
from django.urls import reverse

from django.contrib import admin

from django.conf import settings

# Django settings for secure redirection demonstration
settings.configure(
    DEBUG=True,
    SECRET_KEY='this-is-a-secret-key',
    ROOT_URLCONF=__name__,
)

def secure_view(request):
    # Simulate a secure view that performs safe URL redirection
    redirect_url = request.GET.get('redirect_url', '')
    
    if not redirect_url:
        raise SuspiciousOperation("Invalid Redirect URL")

    # Ensure that the redirection URL belongs to the same domain
    if not redirect_url.startswith('https://example.com'):
        raise SuspiciousOperation("Invalid Redirect Domain")

    return HttpResponseRedirect(redirect_url)

urlpatterns = [
    url(r'^secure/$', secure_view),
]

if __name__ == '__main__':
    from django.core.management import execute_from_command_line
    execute_from_command_line(['script_name', 'runserver'])

