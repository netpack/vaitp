from django.utils.html import escape

def filter_view(request):
    user_input = request.GET.get('filter_param', '')
    sanitized_input = escape(user_input)  # Properly escape user input
    # Use sanitized_input in the query or response