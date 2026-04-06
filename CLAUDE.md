# FenrisHub

Django web application for analyzing FRST (Farbar Recovery Scan Tool) malware scan logs and generating remediation fixlists.

## What it does

Security analysts receive FRST logs from infected Windows machines. FenrisHub lets them:
1. **Upload** FRST log text (paste or file upload, anonymous or authenticated)
2. **Analyze** each log line — the analyzer parses FRST entries (runkeys, services, tasks, firewall rules, etc.) and auto-classifies them using rules
3. **Classify** lines by status: malware (B), PUP (P), clean (C), warning (!), grayware (G), security (S), info (I), junk (J), unknown (?)
4. **Generate fixlists** — remediation scripts built from classified lines
5. **Track infection cases** — group related logs, fixlists, and notes into cases

## Project structure

```
fenrishub/          Django project settings, urls, wsgi
fixlist/            Single Django app — all business logic
  analyzer.py       Rule matching engine, status precedence, line analysis
  frst_extractors.py  FRST log line parsers, FrstEntry dataclass
  models.py         ClassificationRule, Fixlist, UploadedLog, InfectionCase, etc.
  views/            Function-based views (analyzer, uploads, fixlists, rules, cases, auth)
  tests/            22 test files covering views, models, extractors, API
  management/commands/  ensure_superuser, purge_old_trash
templates/          Django templates (extend base.html)
static/
  css/theme.css     CSS variables for theming
  js/log_analyzer/  Analyzer frontend (no build step, no modules)
```

## Key models

- **UploadedLog** — uploaded FRST log with content, analysis stats, two-word upload_id slug
- **ClassificationRule** — match rules (exact/substring/regex/filepath/parsed_entry) with status
- **Fixlist** — generated remediation script, shareable via token
- **InfectionCase** — groups logs + fixlists + notes for a single infection
- **FixlistSnippet** — reusable text snippets for fixlist building

## Tech stack

- Python 3.12, Django 4.2
- SQLite (dev) / PostgreSQL via DATABASE_URL (prod)
- WhiteNoise for static files
- Gunicorn for production (see Procfile)
- No JS build step — vanilla JS in `static/js/` and inline in templates
- No REST framework — JSON APIs are plain Django views

## Commands

```bash
python manage.py test fixlist          # run all tests
python manage.py runserver             # dev server
python manage.py purge_old_trash       # cleanup soft-deleted records
```

## Rule matching

Matcher tiers (first match wins, lower tiers are shadowed):
exact > parsed_entry > filepath > substring > regex

Within a tier, status precedence: B > P > C > ! > G > S > I > J > ?
