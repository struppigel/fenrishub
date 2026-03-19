web: python manage.py migrate && python manage.py ensure_superuser && python manage.py collectstatic --noinput && gunicorn fenrishub.wsgi:application --bind 0.0.0.0:$PORT
