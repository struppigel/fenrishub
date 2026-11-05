from django.db import migrations, models
from django.db.models import F


ANALYZED_LOG_TYPES = ['FRST', 'Addition', 'FRST&Addition']
BATCH_SIZE = 200


def _tag_sources(payload):
    """``(rule_ids, warning_codes)`` the way models._stat_tag_sources reads them."""
    rule_ids = set(payload.get('wholelog_rule_ids') or [])
    for line in payload.get('lines') or []:
        rule_ids.update(line.get('rule_ids') or [])
    codes = set()
    for warning in payload.get('warnings') or []:
        rule_ids.update(warning.get('rule_ids') or [])
        if warning.get('code'):
            codes.add(warning['code'])
    return sorted(rule_ids), sorted(codes)


def backfill_stat_tag_sources(apps, schema_editor):
    """Fill the new fields from each still-present log's fresh shared analysis.

    Snapshots of logs deleted before now keep None: their analysis is gone.
    """
    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    UploadedLogAnalysis = apps.get_model('fixlist', 'UploadedLogAnalysis')
    UploadedLogStat = apps.get_model('fixlist', 'UploadedLogStat')

    def flush(sources):
        stats = list(UploadedLogStat.objects.filter(source_id__in=sources))
        for stat in stats:
            stat.rule_ids, stat.warning_codes = sources[stat.source_id]
        UploadedLogStat.objects.bulk_update(stats, ['rule_ids', 'warning_codes'])

    rows = UploadedLogAnalysis.objects.filter(
        rule_set_key='shared',
        source_content_hash=F('upload__content_hash'),
    ).values_list('upload_id', 'payload')
    pending = {}
    for upload_id, payload in rows.iterator(chunk_size=25):
        if isinstance(payload, dict):
            pending[upload_id] = _tag_sources(payload)
        if len(pending) >= BATCH_SIZE:
            flush(pending)
            pending = {}
    if pending:
        flush(pending)

    # Logs the analyzer skips hold no tags.
    other_ids = UploadedLog.objects.exclude(log_type__in=ANALYZED_LOG_TYPES).values_list('pk', flat=True)
    UploadedLogStat.objects.filter(source_id__in=other_ids, rule_ids__isnull=True).update(
        rule_ids=[], warning_codes=[],
    )


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0085_tagcategory_priority'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedlogstat',
            name='rule_ids',
            field=models.JSONField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='uploadedlogstat',
            name='warning_codes',
            field=models.JSONField(blank=True, default=None, null=True),
        ),
        migrations.RunPython(backfill_stat_tag_sources, migrations.RunPython.noop),
    ]
