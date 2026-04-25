from django.db import migrations


def backfill(apps, schema_editor):
    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    Fixlist = apps.get_model('fixlist', 'Fixlist')
    UploadedLogStat = apps.get_model('fixlist', 'UploadedLogStat')
    FixlistStat = apps.get_model('fixlist', 'FixlistStat')

    log_count_fields = [
        'total_line_count',
        'count_malware', 'count_pup', 'count_clean', 'count_warning',
        'count_grayware', 'count_security', 'count_info', 'count_junk',
        'count_unknown',
        'fixlog_total', 'fixlog_success', 'fixlog_not_found', 'fixlog_error',
    ]

    log_batch = []
    for log in UploadedLog.objects.all().iterator(chunk_size=500):
        creator = log.created_by
        recipient = log.recipient_user
        snapshot = UploadedLogStat(
            source_id=log.pk,
            owner_id=log.created_by_id,
            owner_username=creator.username if creator else '',
            recipient_username=recipient.username if recipient else '',
            log_type=log.log_type,
            created_at=log.created_at,
        )
        for field_name in log_count_fields:
            setattr(snapshot, field_name, getattr(log, field_name))
        log_batch.append(snapshot)
        if len(log_batch) >= 500:
            UploadedLogStat.objects.bulk_create(log_batch, ignore_conflicts=True)
            log_batch = []
    if log_batch:
        UploadedLogStat.objects.bulk_create(log_batch, ignore_conflicts=True)

    fixlist_batch = []
    for fixlist in Fixlist.objects.all().iterator(chunk_size=500):
        owner = fixlist.owner
        fixlist_batch.append(FixlistStat(
            source_id=fixlist.pk,
            owner_id=fixlist.owner_id,
            owner_username=owner.username if owner else '',
            created_at=fixlist.created_at,
            line_count=fixlist.line_count,
        ))
        if len(fixlist_batch) >= 500:
            FixlistStat.objects.bulk_create(fixlist_batch, ignore_conflicts=True)
            fixlist_batch = []
    if fixlist_batch:
        FixlistStat.objects.bulk_create(fixlist_batch, ignore_conflicts=True)


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0047_add_stat_snapshots'),
    ]

    operations = [
        migrations.RunPython(backfill, migrations.RunPython.noop),
    ]
