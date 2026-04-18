import ntpath
import re

from django.db import migrations


STARTUP_RE = re.compile(r"Startup: (.+?)(?: \[([^\]]*)\])?\s*$")
FIREFOX_PROFILE_RE = re.compile(r"(?i)(\\mozilla\\firefox\\profiles\\)[^\\]+")


def normalize_path(path: str) -> str:
    default_username = "username"
    path = path or ""
    if len(path) >= 2 and path[1] == ":" and not path.startswith("C:"):
        path = "C:" + path[2:]
    path = re.sub(r"(?i)(C:\\Users\\)[^\\]+", r"\1" + default_username, path)
    return FIREFOX_PROFILE_RE.sub(r"\1profile", path)


def parse_startup(source_text: str):
    match = STARTUP_RE.match((source_text or "").strip())
    if not match:
        return None
    filepath = normalize_path((match.group(1) or "").strip())
    if not filepath:
        return None
    filename = (ntpath.basename(filepath) or "").strip()
    return {
        "filepath": filepath,
        "normalized_filepath": filepath.lower().strip(),
        "filename": filename,
    }


def convert_startup_exact_rules(apps, schema_editor):
    ClassificationRule = apps.get_model("fixlist", "ClassificationRule")
    qs = ClassificationRule.objects.filter(
        match_type="exact",
        source_text__startswith="Startup:",
    )

    for rule in qs.iterator():
        parsed = parse_startup(rule.source_text)
        if parsed is None:
            continue

        collision = (
            ClassificationRule.objects
            .filter(
                owner_id=rule.owner_id,
                status=rule.status,
                match_type="parsed",
                source_text=rule.source_text,
            )
            .exclude(pk=rule.pk)
            .exists()
        )
        if collision:
            rule.delete()
            continue

        rule.match_type = "parsed"
        rule.entry_type = "startup"
        rule.filepath = parsed["filepath"]
        rule.normalized_filepath = parsed["normalized_filepath"]
        rule.filename = parsed["filename"]
        rule.save(update_fields=[
            "match_type",
            "entry_type",
            "filepath",
            "normalized_filepath",
            "filename",
        ])


class Migration(migrations.Migration):

    dependencies = [
        ("fixlist", "0042_userprofile_word_wrap_default_false"),
    ]

    operations = [
        migrations.RunPython(convert_startup_exact_rules, migrations.RunPython.noop),
    ]
