from django.db import migrations


def backfill_trojan_killer_tool_stats(apps, schema_editor):
    """Trojan Killer logs got a highlighter and B / P / G list chips; fill the
    chips for uploads that already exist. bulk_update leaves updated_at alone."""
    from fixlist.log_highlighting import compute_tool_stats

    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    batch = []
    queryset = UploadedLog.objects.filter(log_type='Trojan Killer').only('id', 'log_type', 'content')
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
        ('fixlist', '0093_userprofile_uploads_all_channels_default'),
    ]

    operations = [
        migrations.RunPython(backfill_trojan_killer_tool_stats, migrations.RunPython.noop),
    ]
