from django.core.urlresolvers import reverse

def vulnerable_reverse(user_input):
    # Directly using user input in reverse can lead to arbitrary code execution
    return reverse(user_input)