import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path):
    """Read KEY=VALUE lines from a local, gitignored .env into the environment.

    Only fills names that are not set already, so a real environment variable
    (e.g. on Railway, which has no .env file) always wins. Blank lines and
    '#' comments are skipped; spaces around '=' and surrounding quotes are
    allowed. A missing or unreadable file is ignored."""
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        name, value = line.split('=', 1)
        name = name.strip()
        if name.startswith('export '):
            name = name[len('export '):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        if name:
            os.environ.setdefault(name, value)


_load_dotenv(BASE_DIR / '.env')


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _env_list(name, default=None):
    value = os.getenv(name)
    if value is None:
        return default or []
    return [item.strip() for item in value.split(',') if item.strip()]


SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-fenrishub-dev-key-change-in-production')

DEBUG = _env_bool('DEBUG', True)
TESTING = 'test' in sys.argv

# centralbox.dev hash lookups (fixlist/centralbox.py). Empty: the feature is
# off and nothing is ever sent; stored verdicts are still shown. Never set
# under the test runner, whatever the shell has: tests opt in explicitly.
CENTRALBOX_API_KEY = '' if TESTING else os.getenv('CENTRALBOX_API_KEY', '').strip()


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


# centralbox budgets, sized for the partner account (per key: 120 report reads
# and 20 fresh lookups per minute), with some headroom. Automatic fresh
# lookups (fixlist/centralbox_auto.py) take part of the shared budget and
# leave the rest to the helpers. Not set under the test runner: tests use the
# defaults in the code or override them.
if not TESTING:
    CENTRALBOX_CALLS_PER_MINUTE = _env_int('CENTRALBOX_CALLS_PER_MINUTE', 110)
    CENTRALBOX_FRESH_LOOKUPS_PER_MINUTE = _env_int('CENTRALBOX_FRESH_LOOKUPS_PER_MINUTE', 18)
    CENTRALBOX_AUTO_FRESH_LOOKUPS_PER_MINUTE = _env_int('CENTRALBOX_AUTO_FRESH_LOOKUPS_PER_MINUTE', 8)
    CENTRALBOX_AUTO_READS_PER_MINUTE = _env_int('CENTRALBOX_AUTO_READS_PER_MINUTE', 60)
    CENTRALBOX_AUTO_FRESH_PER_DAY = _env_int('CENTRALBOX_AUTO_FRESH_PER_DAY', 1000)
    CENTRALBOX_AUTO_FRESH_MAX_RUNNING = _env_int('CENTRALBOX_AUTO_FRESH_MAX_RUNNING', 5)
    CENTRALBOX_AUTO_FRESH_MAX_CANDIDATES_PER_LOG = _env_int('CENTRALBOX_AUTO_FRESH_MAX_CANDIDATES_PER_LOG', 100)

ALLOWED_HOSTS = _env_list('ALLOWED_HOSTS', ['localhost', '127.0.0.1'])
CSRF_TRUSTED_ORIGINS = _env_list('CSRF_TRUSTED_ORIGINS', [])

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'fixlist.apps.FixlistConfig',
]

MIDDLEWARE = [
    'django.middleware.gzip.GZipMiddleware',
    'django.middleware.security.SecurityMiddleware',
    *([] if TESTING else ['whitenoise.middleware.WhiteNoiseMiddleware']),
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'fixlist.middleware.ActionLogMiddleware',
    'fixlist.middleware.OnlineUsersMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'fenrishub.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'fixlist.context_processors.user_display_prefs',
                'fixlist.context_processors.online_users',
                'fixlist.context_processors.moderator_status',
                'fixlist.context_processors.log_type_badges',
                'fixlist.context_processors.tag_category_colors',
            ],
        },
    },
]

WSGI_APPLICATION = 'fenrishub.wsgi.application'

DATABASE_URL = os.getenv('DATABASE_URL')

if DATABASE_URL:
    try:
        dj_database_url = __import__('dj_database_url')
    except ImportError as exc:
        raise RuntimeError('DATABASE_URL is set but dj-database-url is not installed.') from exc

    DATABASES = {
        'default': dj_database_url.parse(
            DATABASE_URL,
            conn_max_age=600,
            ssl_require=not DEBUG,
        )
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

if not TESTING:
    STORAGES = {
        'default': {
            'BACKEND': 'django.core.files.storage.FileSystemStorage',
        },
        'staticfiles': {
            'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage',
        },
    }

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Verbose FRST + Addition logs routinely exceed Django's 2.5 MB default.
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024
# Admin bulk actions can submit one hidden field per selected row.
DATA_UPLOAD_MAX_NUMBER_FIELDS = 50000

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'login'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'fixlist': {
            'handlers': ['console'],
            # Per-action breadcrumbs (see ActionLogMiddleware) are wanted in
            # production but would flood the test runner, which drives hundreds
            # of POSTs. assertLogs sets its own level, so tests that assert on
            # these records still work with the logger quietened here.
            'level': os.getenv('FIXLIST_LOG_LEVEL', 'WARNING' if TESTING else 'INFO'),
            'propagate': False,
        },
    },
}
