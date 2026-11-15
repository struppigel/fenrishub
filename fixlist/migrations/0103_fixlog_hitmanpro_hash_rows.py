from django.db import migrations


def rebuild_fixlog_hitmanpro_hashes(apps, schema_editor):
    """Re-extract the hash rows of Fixlogs with HitmanPro results, whose
    hashes now carry the file's path (and detection) from the item line
    above. Local parsing only (no centralbox call)."""
    from fixlist.file_hashes import extract_file_hashes

    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    UploadedLogFileHash = apps.get_model('fixlist', 'UploadedLogFileHash')
    queryset = (
        UploadedLog.objects.filter(log_type='Fixlog', content__contains='SHA-256')
        .only('id', 'log_type', 'content')
    )
    for upload in queryset.iterator(chunk_size=50):
        rows = extract_file_hashes(upload.log_type, upload.content or '')
        UploadedLogFileHash.objects.filter(upload_id=upload.id).delete()
        UploadedLogFileHash.objects.bulk_create([
            UploadedLogFileHash(
                upload_id=upload.id, sha256=row.sha256, md5=row.md5, line_no=row.line_no,
                anchor_line_no=row.anchor_line_no, path=row.path,
                normalized_path=row.normalized_path, detection=row.detection,
                source=row.source, auto=row.auto,
            )
            for row in rows
        ], batch_size=1000)


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0102_remove_helper_centralbox_keys'),
    ]

    operations = [
        migrations.RunPython(rebuild_fixlog_hitmanpro_hashes, migrations.RunPython.noop),
    ]
