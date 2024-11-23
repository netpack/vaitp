def filter_view(request):
    user_input = request.GET.get('filter_param', '')
    # Improperly handling user input without escaping
    response = f"<div>User input: {user_input}</div>"
    return HttpResponse(response)