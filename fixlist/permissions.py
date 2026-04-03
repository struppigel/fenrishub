"""Permission checks for uploaded logs and other resources."""
from django.contrib.auth.models import User
from .models import UploadedLog


def user_can_delete_uploaded_log(user: User, uploaded_log: UploadedLog) -> bool:
    """
    Check if user can delete an uploaded log.
    
    User can delete if:
    - Log is in general channel (recipient_user is None), OR
    - Log is assigned to the user
    """
    return uploaded_log.recipient_user_id is None or uploaded_log.recipient_user_id == user.id
