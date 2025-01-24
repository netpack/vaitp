from django.shortcuts import redirect
from django.urls import reverse

def my_view(request):
    return redirect(reverse('some-view-name'), foo='bar')
