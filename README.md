# FenrisHub - Secure Fixlist Manager

A minimalistic, terminal-style Django web application for managing and sharing Fixlists securely.

## Features

- **No Self-Registration**: Users are manually added by administrators via Django admin
- **User Authentication**: Login system for defenders
- **Fixlist Management**: Create, edit, and delete fixlists
- **Secure Sharing**: Generate unique share tokens for each fixlist
- **Non-Authenticated Access**: Anyone with a share link can view fixlists
- **Warning Messages**: Recipients are warned that the fixlist is intended for a specific user
- **Easy Copying**: One-click copy-to-clipboard functionality
- **Download Support**: Download fixlists as .txt files
- **Access Logging**: Track who accessed your shared fixlists
- **Terminal Aesthetic**: Green-on-black terminal-style UI


## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

1. **Clone the repository**
   ```bash
   cd FenrisHub
   ```

2. **Create a virtual environment** (required)
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment**
   
   On Windows:
   ```bash
   .\venv\Scripts\activate
   ```
   
   On macOS/Linux:
   ```bash
   source venv/bin/activate
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run migrations**
   ```bash
   python manage.py migrate
   python manage.py makemigrations fixlist
   python manage.py migrate fixlist
   ```

6. **Create a superuser** (required for admin)
   ```bash
   python manage.py createsuperuser
   ```

7. **Run the development server**
   ```bash
   python manage.py runserver
   ```

8. **Access the application**
   - Open your browser and go to `http://localhost:8000`
   - Admin panel: `http://localhost:8000/admin/`

## User Management

**Users are NOT self-registered.** All users must be manually created by an administrator.

### Adding New Users

**Option 1: Via Admin Panel**
1. Login to `http://localhost:8000/admin/`
2. Click on "Users" under Authentication and Authorization
3. Click "Add User" and fill in the details

**Option 2: Via Management Script**
```bash
python manage_users.py
```

This interactive script allows you to:
- Create new users
- List all users
- Delete users
- Grant staff privileges

## Usage

### As a Defender (Logged-in User)

1. **Login**: Use credentials created by an administrator
2. **Create a Fixlist**: 
   - Go to the Dashboard
   - Fill in the title and content
   - Click "CREATE"
3. **Share a Fixlist**:
   - Click "EDIT" on any fixlist
   - Copy the share link from the green box
   - Share this link with anyone (no login required)
4. **Manage Fixlists**:
   - View all your fixlists on the dashboard
   - Edit content at any time
   - Delete fixlists you no longer need

### As a Recipient (Non-Logged-in User)

1. **Access a Fixlist**: Click the shared link sent by a defender
2. **View the Content**: Read the fixlist with a warning message
3. **Copy Content**: Click "COPY_ALL" to copy all text to clipboard
4. **Download**: Click "DOWNLOAD" to save as a .txt file


## Project Structure

```
FenrisHub/
├── fenrishub/                 # Main project folder
│   ├── __init__.py
│   ├── settings.py           # Django settings
│   ├── urls.py               # URL configuration
│   └── wsgi.py
├── fixlist/                  # Main app
│   ├── migrations/
│   ├── __init__.py
│   ├── admin.py             # Django admin configuration
│   ├── apps.py
│   ├── forms.py             # Django forms
│   ├── models.py            # Database models
│   ├── urls.py              # App URL patterns
│   └── views.py             # View functions
├── templates/               # HTML templates
│   ├── base.html           # Base template with styling
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── view_fixlist.html
│   └── shared_fixlist.html
├── manage.py
└── requirements.txt
```

## Models

### Fixlist
- `owner`: Foreign key to User
- `title`: Title of the fixlist
- `content`: The actual content (text)
- `share_token`: Unique 32-character token for sharing
- `created_at`: Creation timestamp
- `updated_at`: Last update timestamp
- `is_public`: Boolean flag (for future features)

### AccessLog
- `fixlist`: Foreign key to Fixlist
- `accessed_at`: When it was accessed
- `ip_address`: IP of the visitor
- `user_agent`: Browser user agent

## API Endpoints

- `GET /` - Login page
- `POST /` - Login action
- `GET/POST /register/` - Registration
- `GET/POST /dashboard/` - User dashboard
- `GET/POST /fixlist/<id>/` - Edit fixlist
- `GET /share/<token>/` - View shared fixlist
- `GET /download/<token>/` - Download fixlist as text
- `POST /logout/` - Logout

## Security Notes

- Change `SECRET_KEY` in `settings.py` before production
- Set `DEBUG = False` in production
- Set `ALLOWED_HOSTS` to your domain(s) in production
- Use HTTPS in production
- Use a proper database (PostgreSQL/MySQL) instead of SQLite in production
- Set up proper authentication and CSRF protection

## Terminal Styling

The application features a minimalist terminal aesthetic:
- Black background (#0a0a0a)
- Green text (#00ff00) - Classic terminal style
- Monospace font (Courier New)
- Glow effects on interactions
- Command-line style UI

## Future Enhancements

- Export multiple fixlists as archive
- Search functionality
- Fixlist categories/tags
- Expiring share links
- Password-protected shares
- Integration with external storage
- Dark/Light theme toggle

## License

MIT License - Feel free to use and modify

## Support

For issues or questions, please check the documentation or create an issue in the repository.
