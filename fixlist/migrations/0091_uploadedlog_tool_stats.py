from django.db import migrations, models


# Kept in sync with fixlist.log_highlighting.compute_tool_stats: the types
# that get list-view chips. Fixlog / FRST keep their dedicated count fields.
TOOL_STAT_TYPES = [
    'MAU', 'ESET', 'Malwarebytes', 'HitmanPro', 'Emsisoft', 'AdwCleaner',
    'Shortcut', 'KpRm', 'SecurityCheck', 'FRST Search',
]


def backfill_tool_stats(apps, schema_editor):
    """Fill the new chips for existing uploads. Only the small tool logs are
    touched (each takes ~1 ms); rows are written in batches with
    bulk_update, which leaves updated_at alone."""
    from fixlist.log_highlighting import compute_tool_stats

    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    batch = []
    queryset = UploadedLog.objects.filter(log_type__in=TOOL_STAT_TYPES).only('id', 'log_type', 'content')
    for upload in queryset.iterator(chunk_size=200):
        upload.tool_stats = compute_tool_stats(upload.log_type, upload.content or '')
        batch.append(upload)
        if len(batch) >= 200:
            UploadedLog.objects.bulk_update(batch, ['tool_stats'])
            batch = []
    if batch:
        UploadedLog.objects.bulk_update(batch, ['tool_stats'])


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0090_regex_rules_color_matched_text'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedlog',
            name='tool_stats',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.RunPython(backfill_tool_stats, migrations.RunPython.noop),
    ]
