from django.shortcuts import redirect

def my_view(request):
    return redirect(url_for('some-view-name'), foo='bar')