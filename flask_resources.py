from flask_login import UserMixin

class User(UserMixin):
    """
    This is YOUR custom class - you write this!
    """
    def __init__(self, username):
        self.id = username      # MUST be called 'id' (Flask-Login requirement)
        # Add whatever fields you want:
        # self.is_admin = is_admin
        # self.created_at = created_at
        # etc.

    @classmethod
    def get(self, user_id):
        return User(user_id)