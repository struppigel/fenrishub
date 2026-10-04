import re

from django.db import migrations
from django.db.models import Q


# Translated `[File not signed]` tags, which the parser now recognizes. Rules
# whose source line carries one were stored with file_not_signed=False.
TRANSLATED_NOT_SIGNED_TAGS = (
    "[Archivo no firmado]",
    "[Arquivo não assinado]",
    "[Fichier non signé]",
    "[Datei ist nicht signiert]",
    "[Brak podpisu cyfrowego]",
    "[Файл не подписан]",
    "[文件未签名]",
)

# The process and .job patterns before this migration. An exact rule is only
# converted when these could not read its line, i.e. when it is exact for lack
# of a parser. Exact rules for lines that already parsed stay as they were made.
OLD_PROCESS_RE = re.compile(r"(\((.* )->\) )?\((.*)\) (\w:\\[^\<]*?)( \<\d+\>)?$")
OLD_JOB_RE = re.compile(
    r'Task:\s+(.+?\.job)\s*=>\s*"?(.+?\.(?:exe|dll|bat|cmd|ps1|scr|vbs|wsf|com|msi))"?'
)


def _newly_parseable(source_text):
    from fixlist import frst_extractors as ex

    text = (source_text or "").strip()
    if ex.extract_process(text) and not OLD_PROCESS_RE.match(text):
        return True
    if ex.extract_frst_scheduled_task_job(text) and not OLD_JOB_RE.match(text):
        return True
    return ex.extract_frst_startup_dir(text) is not None


def reparse_process_and_job_rules(apps, schema_editor):
    # The current parser on purpose, not a frozen copy as in 0043: the stored
    # fields must equal what the analyzer computes from log lines from now on.
    from fixlist.analyzer import convert_exact_rules_to_parsed, reparse_rules

    ClassificationRule = apps.get_model("fixlist", "ClassificationRule")

    # Process parents and .job paths in `name` are now normalized and lowercased.
    translated = Q()
    for tag in TRANSLATED_NOT_SIGNED_TAGS:
        translated |= Q(source_text__contains=tag)
    reparse_rules(
        ClassificationRule.objects.filter(match_type="parsed").filter(
            Q(entry_type__in=("process", "scheduled_task")) | translated
        ),
        apply=True,
    )

    # Unsigned process lines, uppercase-.EXE .job lines and StartupDir lines used
    # to be stored as exact rules because nothing parsed them.
    exact = ClassificationRule.objects.filter(match_type="exact")
    newly_parseable = [
        pk for pk, source_text in exact.values_list("pk", "source_text") if _newly_parseable(source_text)
    ]
    convert_exact_rules_to_parsed(
        exact.filter(pk__in=newly_parseable),
        entry_types=("process", "scheduled_task", "startup_dir"),
    )


class Migration(migrations.Migration):

    dependencies = [
        ("fixlist", "0074_classificationrule_color_whole_line"),
    ]

    operations = [
        migrations.RunPython(reparse_process_and_job_rules, migrations.RunPython.noop),
    ]
