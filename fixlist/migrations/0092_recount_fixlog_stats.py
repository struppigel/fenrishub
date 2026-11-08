from django.db import migrations


FIELDS = ['fixlog_total', 'fixlog_success', 'fixlog_not_found', 'fixlog_error']


def recount_fixlog_stats(apps, schema_editor):
    """Fixlog ops used to include the echoed fixlist's ` => ` lines; recount
    stored Fixlogs and their /stats/ snapshots with the fixed counter.
    bulk_update leaves updated_at alone."""
    from fixlist.models import count_fixlog_results

    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    UploadedLogStat = apps.get_model('fixlist', 'UploadedLogStat')

    batch = []
    recounted = {}
    for upload in UploadedLog.objects.filter(log_type='Fixlog').only('id', 'content').iterator(chunk_size=50):
        counts = count_fixlog_results(upload.content or '')
        upload.fixlog_total = counts['total']
        upload.fixlog_success = counts['success']
        upload.fixlog_not_found = counts['not_found']
        upload.fixlog_error = counts['error']
        upload.content = None  # don't keep large logs alive in the batch
        recounted[upload.id] = counts
        batch.append(upload)
        if len(batch) >= 50:
            UploadedLog.objects.bulk_update(batch, FIELDS)
            batch = []
    if batch:
        UploadedLog.objects.bulk_update(batch, FIELDS)

    snapshots = []
    for snapshot in UploadedLogStat.objects.filter(source_id__in=list(recounted)).only('id', 'source_id'):
        counts = recounted[snapshot.source_id]
        snapshot.fixlog_total = counts['total']
        snapshot.fixlog_success = counts['success']
        snapshot.fixlog_not_found = counts['not_found']
        snapshot.fixlog_error = counts['error']
        snapshots.append(snapshot)
    UploadedLogStat.objects.bulk_update(snapshots, FIELDS, batch_size=200)


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0091_uploadedlog_tool_stats'),
    ]

    operations = [
        migrations.RunPython(recount_fixlog_stats, migrations.RunPython.noop),
    ]
