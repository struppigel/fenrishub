# FenrisHub Quick Start

This guide is for getting a local FenrisHub instance running quickly and walking through the main workflows.

## 1. Create a local environment

From the repository root:

```bash
python -m venv venv
```

Windows:

```bash
.\venv\Scripts\activate
```

macOS/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Apply migrations:

```bash
python manage.py migrate
```

## 2. Create an admin account

FenrisHub does not support self-registration. Create a superuser first:

```bash
python manage.py createsuperuser
```

Then start the dev server:

```bash
python manage.py runserver
```

Open:

- App: `http://localhost:8000`
- Admin: `http://localhost:8000/admin/`

## 3. Add analyst users

Create users in one of two ways.

### Option 1: Django admin

1. Sign in to `/admin/`
2. Open Users under Authentication and Authorization
3. Add a user
4. Optionally grant staff access

### Option 2: helper script

```bash
python manage_users.py
```

The helper script can create, list, and delete users.

## 4. First login

Go to `/` and sign in with the account you created.

Useful authenticated routes:

- `/dashboard/`
- `/uploads/`
- `/fixlists/analyze/`
- `/rules/`
- `/fixlists/snippets/`

## 5. Test the upload flow

FenrisHub accepts uploads from unauthenticated users at `/upload/`.

You can test either of these:

- upload a `.txt` file
- paste log text directly into the form

After submission, the app stores the content as an `UploadedLog`, detects the log type, calculates analysis stats, and returns a memorable upload ID.

Notes:

- anonymous uploads are rate-limited by IP
- usernames are expected in Reddit-style format without the `u/` prefix
- uploads can be FRST, Addition, combined FRST+Addition, Fixlog, or Unknown

## 6. Review uploaded logs

As an authenticated user, go to `/uploads/`.

From there you can:

- open a single upload
- rename the stored Reddit username on an upload
- select multiple uploads and merge them
- compare two uploads with the diff view
- move uploads to trash and restore them later

## 7. Use the analyzer

Open `/fixlists/analyze/`.

The analyzer can:

- classify lines with stored rules
- show warnings for incomplete logs and other conditions
- inspect how a specific line matched rules
- let you change statuses in the UI
- preview optional rule persistence before saving changes as rules

Important behavior:

- status overrides are validated first
- analyzer changes do not have to be persisted immediately
- rule preview and persistence use dedicated API routes

## 8. Create and share a fixlist

Authenticated users can create fixlists at `/fixlists/create/` and manage them from `/dashboard/`.

Each fixlist:

- is owned by a user
- has a unique share token
- can include an internal note for logged-in use
- can be downloaded as text
- can be accessed publicly by share link

Public routes:

- `/share/<token>/`
- `/download/<token>/`

## 9. Manage rules and snippets

### Rules

Go to `/rules/` to manage classification rules.

Supported rule match types:

- exact
- substring
- regex
- filepath
- parsed

Rules are owner-scoped and can be enabled or disabled.

### Snippets

Go to `/fixlists/snippets/` to manage reusable fixlist snippets.

Snippets can be:

- private to the owner
- shared with other authenticated users

## 10. Optional environment configuration

For local work, the app defaults to SQLite if `DATABASE_URL` is not set.

Common environment variables:

- `SECRET_KEY`
- `DEBUG`
- `ALLOWED_HOSTS`
- `CSRF_TRUSTED_ORIGINS`
- `DATABASE_URL`
- `ANON_UPLOAD_RATE_LIMIT_COUNT`
- `ANON_UPLOAD_RATE_LIMIT_WINDOW_SECONDS`

Optional deploy-time superuser bootstrap:

- `AUTO_CREATE_SUPERUSER=true`
- `DJANGO_SUPERUSER_USERNAME`
- `DJANGO_SUPERUSER_PASSWORD`
- `DJANGO_SUPERUSER_EMAIL`

## 11. Stopping the server

Press `Ctrl+C` in the terminal running `python manage.py runserver`.

## 12. Common local commands

```bash
python manage.py runserver
python manage.py migrate
python manage.py createsuperuser
python manage.py test
python manage_users.py
```

## 13. If something looks wrong

- confirm the virtual environment is active
- confirm dependencies from `requirements.txt` are installed
- run `python manage.py migrate`
- verify you are opening the routes listed above instead of older docs or bookmarks
