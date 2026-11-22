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

## Shared helpers (reuse instead of re-implementing)

- `fixlist/regex_engine.py` — re2-first compile, re2 Sets, match ranges; `regex_bench.py` — slow-regex probes
- `fixlist/status_types.py` — status codes, `dominant_status`, `precedence_rank`, `STATUS_PAINT`
- `fixlist/log_types.py` — built-in log type names and groups; `trash.py` + `SoftDeleteQuerySet` (`.live()`, `.trashed()`, `.move_to_trash()`)
- `fixlist/background.py` — `start()` for work off the request thread
- `fixlist/views/utils.py`, `api_params.py`, `validators.PayloadValidator.json_object` — request parsing helpers
- `fixlist/views/library_items.py` — snippets and speeches share list/validation/selection code
- `static/js/common.js` (`Fenris.*`: CSRF, JSON requests, clipboard, storage, status maps) is loaded on every page;
  also `popup_menu.js`, `correlation_format.js`, `rule_form.js`, `rule_highlight.js`, `library_page.js`
- `static/css/components.css` — shared buttons, tabs, modal backdrop, tables
- `fixlist/log_layout.py` — `analyzed_lines` (the analyzer's line walk with log page line numbers; pair
  payload entries with log lines through it), `layout` (block and section of each line)
- `fixlist/fact_service.py` — facts outside the analyzer: names at serve time, condition keys, invalidation

## Rule matching

Every rule has a numeric priority (0-20, default by match type: exact 19, parsed 15, filepath 11,
substring 7, regex/script 3). The highest priority on a line decides; lower ones are shadowed.
Within it, status precedence: B > P > C > ! > G > S > I > J > ?

Facts (advanced): a `Fact` is found by `FactRule`s (own pattern, never a status) and `FactTagSource`s
(classification rules with a tag that matched). A classification rule with `RuleCondition`s
(require/forbid a fact in its block, section or the log) applies only where all hold. Analysis runs in
two passes: rules without conditions and facts first, then conditional rules on the lines they matched;
conditional rules never feed facts, so there are no cycles. `ClassificationRule.condition_key` is part of
a rule's identity: lookups of "the same rule" must include it (plain rules have '').
