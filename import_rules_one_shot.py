from pathlib import Path

from django.db.models import Count

from fixlist.analyzer import import_rules_from_lines
from fixlist.models import ClassificationRule

base = Path("Fenris")

personal_sources = [
    ("B", "badlist.txt"),
    ("P", "puplist.txt"),
    ("C", "clean.txt"),
    ("!", "warnlist.txt"),
    ("G", "graylist.txt"),
    ("S", "securitylist.txt"),
    ("I", "infolist.txt"),
    ("J", "junklist.txt"),
]

# Map legacy systemlookup db_* files to current userdefined states.
# X->B (malware), Y/L->C (clean/legitimate), O->! (warning),
# U->C (clean/user-choice), N->P (potentially unwanted/not required).
mapped_systemlookup_sources = [
    ("B", "db_x"),
    ("C", "db_y"),
    ("C", "db_l"),
    ("!", "db_o"),
    ("C", "db_u"),
    ("P", "db_n"),
]

sources = personal_sources + mapped_systemlookup_sources

print("INITIAL_RULES", ClassificationRule.objects.count())
print("MAPPED_DB_SOURCES", mapped_systemlookup_sources)

for status, filename in sources:
    file_path = base / filename
    if not file_path.exists():
        print(f"{status} {filename}: missing file, skipped")
        continue

    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    result = import_rules_from_lines(lines, status=status, source_name=filename)
    print(
        f"{status} {filename}: "
        f"created={result['created']} "
        f"updated={result['updated']} "
        f"skipped={result['skipped']} "
        f"invalid={result['invalid']}"
    )

print("TOTAL_RULES", ClassificationRule.objects.count())
print(
    "BY_STATUS",
    list(ClassificationRule.objects.values("status").annotate(c=Count("id")).order_by("status")),
)
print(
    "BY_SOURCE",
    list(
        ClassificationRule.objects.values("source_name")
        .annotate(c=Count("id"))
        .order_by("source_name")
    ),
)
