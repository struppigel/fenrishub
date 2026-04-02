# FenrisHub

FenrisHub is a Django application for FRST/Fixlog intake, line-by-line analysis, rule management, and fixlist sharing. It started as a secure fixlist manager and now also includes public log upload, analyst review workflows, reusable snippets, and owner-scoped classification rules.

## What It Does

- Accepts pasted or uploaded `.txt` logs through a public upload form
- Detects FRST, Addition, combined FRST+Addition, and Fixlog content
- Analyzes uploaded logs into per-line status classifications and warnings
- Lets authenticated users inspect, diff, merge, rename, trash, and restore uploads
- Supports owner-scoped classification rules for exact, substring, regex, filepath, and parsed-entry matching
- Lets analysts build and share fixlists with tokenized public links
- Stores reusable fixlist snippets, including optionally shared snippets for other authenticated users
- Preserves a terminal-style UI while using static assets and Django templates

## Main Workflows

### Public users

- Submit a FRST or Fixlog text file at `/upload/`
- Paste log text instead of uploading a file
- Receive a memorable upload ID after submission
- Open shared fixlist links without authentication

Anonymous uploads are rate-limited by client IP.

### Authenticated analysts

- Review uploaded logs from `/uploads/`
- Open a log by memorable upload ID
- Compare two uploads side by side
- Merge multiple uploads into a new combined upload
- Run analyzer workflows from `/fixlists/analyze/`
- Preview and optionally persist analyzer-derived rules
- Create fixlists from analyzed content
- Manage their own classification rules and snippets
- Soft-delete and restore both uploads and fixlists from trash views

## Core Data Model

### Fixlist

User-owned remediation content with a title, freeform text, internal note, soft-delete support, download count, and a unique share token for public access.

### AccessLog

Audit record for public fixlist access, including timestamp, IP address, and user agent.

### UploadedLog

Stored raw log content with Reddit username, original filename, memorable `upload_id`, content hash, detected log type, incomplete-log flag, and cached analysis counters.

### ClassificationRule

Owner-scoped rules that classify lines by status using one of five match types:

- `exact`
- `substring`
- `regex`
- `filepath`
- `parsed`

Rules can carry parsed metadata such as CLSID, filepath, filename, company, arguments, and signature state.

### FixlistSnippet

Reusable content blocks owned by a user and optionally shared with other authenticated users.

### ParsedFilepathExclusion

Normalized file paths that should be excluded or treated specially when parsed filepath matching would otherwise create noise.

## Analyzer Notes

The analyzer in `fixlist/analyzer.py` parses FRST-style lines, evaluates them against stored rules, and emits warnings for common conditions such as:

- incomplete FRST/Addition logs
- low-memory or low-disk conditions visible in the log
- multiple enabled antivirus products

Analyzer overrides are validated first and can later be previewed and optionally persisted as rules.

## Project Layout

```text
FenrisHub/
├── fenrishub/                  # Django project settings and root URLConf
├── fixlist/                    # Main application: models, views, analyzer, forms, admin
│   ├── management/commands/    # Utility commands such as ensure_superuser
│   ├── migrations/
│   └── tests/
├── templates/                  # Django templates for uploads, analyzer, rules, snippets, fixlists
├── static/                     # CSS and JavaScript assets
├── Fenris/                     # FRST parsing/reference assets and legacy helper scripts
├── manage.py
├── manage_users.py             # Interactive local user-management helper
├── requirements.txt
├── Procfile
└── railway.toml
```

## Local Setup

### Prerequisites

- Python 3.8+
- pip

### Install

1. Create and activate a virtual environment.

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

2. Install dependencies.

```bash
pip install -r requirements.txt
```

3. Run migrations.

```bash
python manage.py migrate
```

4. Create an admin account.

```bash
python manage.py createsuperuser
```

5. Start the development server.

```bash
python manage.py runserver
```

6. Open the app.

- App: `http://localhost:8000`
- Admin: `http://localhost:8000/admin/`

## User Management

Self-registration is not enabled. Users must be created by an administrator.

### Option 1: Django admin

Create users from `/admin/` under Authentication and Authorization.

### Option 2: helper script

```bash
python manage_users.py
```

The script supports creating, listing, and deleting users, plus optionally granting staff access.

## Configuration

FenrisHub is configured primarily through environment variables.

### Common settings

- `SECRET_KEY`: Django secret key
- `DEBUG`: `true` or `false`
- `ALLOWED_HOSTS`: comma-separated hostnames
- `CSRF_TRUSTED_ORIGINS`: comma-separated trusted origins
- `DATABASE_URL`: optional database URL; if omitted, SQLite is used

### Anonymous upload rate limiting

- `ANON_UPLOAD_RATE_LIMIT_COUNT`: max anonymous uploads per window, default `15`
- `ANON_UPLOAD_RATE_LIMIT_WINDOW_SECONDS`: window length in seconds, default `3600`

### Optional automatic superuser bootstrap

The `ensure_superuser` management command will create or update a superuser during deploy if these are set:

- `AUTO_CREATE_SUPERUSER=true`
- `DJANGO_SUPERUSER_USERNAME`
- `DJANGO_SUPERUSER_PASSWORD`
- `DJANGO_SUPERUSER_EMAIL` (optional)

## Deployment

The repo includes deployment config for Gunicorn and Railway-style platforms.

### Procfile

The web process runs migrations, applies optional superuser bootstrap, and starts Gunicorn.

### railway.toml

The Railway config:

- runs `collectstatic` at build time
- runs tests, migrations, and `ensure_superuser` before deploy
- starts `gunicorn fenrishub.wsgi:application`

When `DEBUG` is false, WhiteNoise is enabled for static file serving and secure cookie settings are applied.

## Key Routes

- `/` login page
- `/upload/` public upload form
- `/dashboard/` authenticated fixlist dashboard
- `/uploads/` uploaded log management
- `/fixlists/analyze/` log analyzer UI
- `/rules/` classification rule management
- `/fixlists/snippets/` snippet management
- `/share/<token>/` public fixlist view
- `/download/<token>/` fixlist text download

## Development Notes

- The primary application logic lives in `fixlist/`
- Static assets live in `static/`
- Templates live in `templates/`
- Global site colors should use CSS variables from `static/css/theme.css`
- In production, prefer a real database via `DATABASE_URL` instead of local SQLite

## License

MIT
