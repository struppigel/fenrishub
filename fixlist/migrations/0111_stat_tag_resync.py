from django.db import migrations, models
from django.db.models import F


BATCH_SIZE = 200


def _flush(UploadedLogStat, values, fields):
    """Write `values` ({source_id: {field: value}}) to the stats whose value differs."""
    changed = []
    for stat in UploadedLogStat.objects.filter(source_id__in=values):
        new = values[stat.source_id]
        if any(getattr(stat, field) != new[field] for field in fields):
            for field in fields:
                setattr(stat, field, new[field])
            changed.append(stat)
    if changed:
        UploadedLogStat.objects.bulk_update(changed, fields)


def resync_stat_tags(apps, schema_editor):
    """Point every snapshot at its log's cached shared analysis and correlations.

    Until now only a full recalculation wrote a snapshot's tag sources, so a
    log re-analyzed by opening it (after new tagged rules were added) kept
    the old ones. Reads the small `tag_summary` / `line_tags` columns; a
    payload is decoded only for a row without a summary. The correlated
    SHA256s come from each log's most recently stored correlations.
    """
    from fixlist.case_correlations import correlated_sha256s
    from fixlist.tagging import line_tag_hits, tag_summary_of

    UploadedLogAnalysis = apps.get_model('fixlist', 'UploadedLogAnalysis')
    UploadedLogStat = apps.get_model('fixlist', 'UploadedLogStat')
    CorrelationCache = apps.get_model('fixlist', 'CorrelationCache')

    tag_fields = ['rule_ids', 'warning_codes', 'line_tag_ids']
    rows = UploadedLogAnalysis.objects.filter(
        rule_set_key='shared', source_content_hash=F('upload__content_hash'),
    ).values_list('pk', 'upload_id', 'tag_summary', 'line_tags')
    pending = {}
    for pk, upload_id, summary, line_tags in rows.iterator(chunk_size=500):
        if summary is None:
            payload = UploadedLogAnalysis.objects.filter(pk=pk).values_list('payload', flat=True).first()
            summary = tag_summary_of(payload)
            if summary is None:
                continue
        pending[upload_id] = {
            'rule_ids': sorted(summary.get('rule_ids') or []),
            'warning_codes': sorted(summary.get('codes') or []),
            'line_tag_ids': sorted(line_tag_hits(line_tags)),
        }
        if len(pending) >= BATCH_SIZE:
            _flush(UploadedLogStat, pending, tag_fields)
            pending = {}
    if pending:
        _flush(UploadedLogStat, pending, tag_fields)

    # Ordered so each log's latest stored answer is the one kept.
    answers = CorrelationCache.objects.order_by('upload_id', 'updated_at').values_list('upload_id', 'payload')
    pending = {}
    for upload_id, answer in answers.iterator(chunk_size=50):
        if upload_id not in pending and len(pending) >= BATCH_SIZE:
            _flush(UploadedLogStat, pending, ['correlated_sha256s'])
            pending = {}
        pending[upload_id] = {'correlated_sha256s': correlated_sha256s(answer)}
    if pending:
        _flush(UploadedLogStat, pending, ['correlated_sha256s'])


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0110_spor_link_details'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedlogstat',
            name='correlated_sha256s',
            field=models.JSONField(blank=True, default=None, null=True),
        ),
        migrations.RunPython(resync_stat_tags, migrations.RunPython.noop),
    ]
