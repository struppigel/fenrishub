# FenrisHub - Quick Start Guide

## Initial Setup

This project has been created with **no user registration**. All users must be manually created by an administrator using the Django admin panel.

### 1. Run the development server

```bash
cd c:\Users\strup\Repos\FenrisHub
.\venv\Scripts\activate
python manage.py runserver
```

The application will be available at `http://localhost:8000`

### 2. Create a superuser (admin account)

```bash
python manage.py createsuperuser
```

Follow the prompts to create an admin account. You'll need:
- Username
- Email (can be blank)
- Password (twice for confirmation)

### 3. Add defender users via admin

1. Go to `http://localhost:8000/admin/`
2. Login with your superuser credentials
3. Click on "Users" under Authentication and Authorization
4. Click "Add User" button
5. Enter username and password, then save
6. (Optional) Make them staff members or give them permissions

### 4. Users can now login

Users can login at `http://localhost:8000` with their credentials.

## User Management Commands (Optional)

You can also create users from the command line:

```bash
python manage.py shell
```

Then in the Python shell:

```python
from django.contrib.auth.models import User

# Create a new user
User.objects.create_user(username='defender_name', password='secure_password')

# Exit the shell
exit()
```

## User Workflow

### For Defenders (Logged-in users):
1. Login with credentials
2. Create a Fixlist by providing a title and pasting/typing content
3. Copy the share link
4. Share it with anyone (they don't need to login)

### For Recipients (Non-logged-in users):
1. Receive a share link
2. Click the link - they'll see a warning that it's meant for a specific user
3. Copy the content or download as a .txt file
4. No login required

## Admin Features

Access the admin panel at `/admin/`:
- Manage users and permissions
- View all fixlists and who owns them
- Track access logs for shared fixlists
- Delete or modify fixlists if needed

## Stopping the Server

Press `Ctrl+C` in your terminal to stop the development server.

## Important Notes

- The database is SQLite (db.sqlite3) - fine for development
- For production, use PostgreSQL or MySQL
- Change the SECRET_KEY in settings.py before deploying
- Set DEBUG = False in production settings.py
- Update ALLOWED_HOSTS with your domain
