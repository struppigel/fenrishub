import re

from django.db import migrations


# The One Month pattern before FRST's bracket tags (frst_tags.py) were understood:
# the path had to follow the company directly. Exact rules for lines it could
# not read were exact for lack of a parser and become parsed rules now.
OLD_ONEMONTH_RE = re.compile(
    r"(?:Found path already in\s+)?"
    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})? - \d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?"
    r" - \d+ (.{5}) (\((.*)\) )?(\w:\\.*)"
)


def _newly_parseable(source_text):
    from fixlist import frst_extractors as ex

    text = (source_text or "").strip()
    return ex.extract_onemonth(text) is not None and not OLD_ONEMONTH_RE.match(text)


def reparse_after_tag_list(apps, schema_editor):
    # The current parser on purpose, as in 0075: the stored fields must equal
    # what the analyzer computes from log lines from now on.
    from fixlist.analyzer import convert_exact_rules_to_parsed, reparse_rules

    ClassificationRule = apps.get_model("fixlist", "ClassificationRule")

    # Tags in any listed language no longer leak into company, date, arguments
    # or the path of services, Run keys, startup, tasks, firewall rules and
    # processes. Re-parsing is idempotent, so every parsed rule is checked.
    reparse_rules(ClassificationRule.objects.filter(match_type="parsed"), apply=True)

    exact = ClassificationRule.objects.filter(match_type="exact")
    newly_parseable = [
        pk for pk, source_text in exact.values_list("pk", "source_text") if _newly_parseable(source_text)
    ]
    convert_exact_rules_to_parsed(exact.filter(pk__in=newly_parseable), entry_types=("onemonth",))


class Migration(migrations.Migration):

    dependencies = [
        ("fixlist", "0075_reparse_process_and_job_rules"),
    ]

    operations = [
        migrations.RunPython(reparse_after_tag_list, migrations.RunPython.noop),
    ]
