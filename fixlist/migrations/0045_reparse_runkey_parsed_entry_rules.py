"""Re-parse stored parsed-entry rules whose entry_type is 'runkey'.

Background: extract_frst_runkey previously had its `date` and `company` group_map
entries swapped, so runkey rules created before the fix have the date string
persisted in the `company` column (and no `date` column exists on the model).
After the fix, freshly-parsed runkey lines have the real company name, which
breaks FrstEntry equality against the stored rules.

This migration re-parses the source_text of each affected rule with the now-
correct extractor and writes back any changed parsed metadata fields.
"""

from django.db import migrations

from fixlist import frst_extractors as ex


PARSED_FIELDS = (
    "clsid",
    "name",
    "filepath",
    "filename",
    "company",
    "arguments",
    "file_not_signed",
)


def reparse_runkey_rules(apps, schema_editor):
    ClassificationRule = apps.get_model("fixlist", "ClassificationRule")

    # NB: ClassificationRule.MATCH_PARSED_ENTRY is the constant name, but its
    # stored value is "parsed" (not "parsed_entry").
    qs = ClassificationRule.objects.filter(
        match_type="parsed",
        entry_type="runkey",
    )

    for rule in qs.iterator():
        entry = ex.extract_frst_runkey(rule.source_text or "")
        if entry is None or entry.entry_type != "runkey":
            continue

        normalized_filepath = (
            ex.normalize_path(entry.filepath).lower().strip()
            if entry.filepath
            else ""
        )

        new_values = {
            "clsid": entry.clsid,
            "name": entry.name,
            "filepath": entry.filepath,
            "filename": entry.filename,
            "company": entry.company,
            "arguments": entry.arguments,
            "file_not_signed": entry.file_not_signed,
            "normalized_filepath": normalized_filepath,
        }

        changed_fields = [
            field for field, value in new_values.items() if getattr(rule, field) != value
        ]
        if not changed_fields:
            continue

        for field in changed_fields:
            setattr(rule, field, new_values[field])
        rule.save(update_fields=changed_fields)


class Migration(migrations.Migration):

    dependencies = [
        ("fixlist", "0044_userprofile_analyzer_fixlist_template"),
    ]

    operations = [
        migrations.RunPython(reparse_runkey_rules, migrations.RunPython.noop),
    ]
