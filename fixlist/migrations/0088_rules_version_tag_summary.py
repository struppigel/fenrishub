from django.db import migrations, models

BATCH_SIZE = 25


def _summary(payload):
    # Frozen copy of tagging.tag_summary_of as of this migration.
    if not isinstance(payload, dict):
        return None
    rule_ids = set(payload.get('wholelog_rule_ids') or [])
    for line in payload.get('lines') or []:
        rule_ids.update(line.get('rule_ids') or [])
    for warning in payload.get('warnings') or []:
        rule_ids.update(warning.get('rule_ids') or [])
    return {
        'format': payload.get('format'),
        'rule_ids': sorted(rule_ids),
        'codes': sorted({
            warning.get('code') for warning in payload.get('warnings') or []
            if isinstance(warning.get('code'), str)
        }),
    }


def backfill_tag_summary(apps, schema_editor):
    UploadedLogAnalysis = apps.get_model('fixlist', 'UploadedLogAnalysis')
    pks = list(UploadedLogAnalysis.objects.filter(tag_summary__isnull=True).values_list('pk', flat=True))
    for start in range(0, len(pks), BATCH_SIZE):
        batch = UploadedLogAnalysis.objects.filter(pk__in=pks[start:start + BATCH_SIZE]).values_list('pk', 'payload')
        for pk, payload in batch:
            UploadedLogAnalysis.objects.filter(pk=pk).update(tag_summary=_summary(payload))


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0087_tag_log_line_matching'),
    ]

    operations = [
        migrations.AddField(
            model_name='siteconfig',
            name='rules_version',
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name='uploadedloganalysis',
            name='tag_summary',
            field=models.JSONField(blank=True, default=None, null=True),
        ),
        migrations.RunPython(backfill_tag_summary, migrations.RunPython.noop),
    ]
