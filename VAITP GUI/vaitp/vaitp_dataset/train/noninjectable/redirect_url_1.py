from django.shortcuts import redirect

def my_view(request):
    return redirect('some-view-name', foo='bar')