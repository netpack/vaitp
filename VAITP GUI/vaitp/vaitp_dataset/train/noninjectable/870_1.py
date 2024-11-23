def update_user_profile(user_id, profile_data):
    # Directly updating the user profile without sanitization
    # This can lead to arbitrary code execution if profile_data contains malicious code
    save_user_profile(user_id, profile_data)

def display_document(document):
    # Directly rendering content that may contain user input with wiki syntax
    # This can allow execution of arbitrary macros
    return render_content(document.content)