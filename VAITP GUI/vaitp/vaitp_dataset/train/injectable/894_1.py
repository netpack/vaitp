
class UserProfile:
    def __init__(self, username):
        self.username = username
        self.profile_data = {}
        self.notifications_settings = {}

    def edit_profile(self, new_data):
        # Implement proper data validation and sanitization logic
        # Raise an exception if validation fails
        pass

    def edit_notifications(self, new_settings):
        # Implement proper data validation and sanitization logic
        # Raise an exception if validation fails
        pass