from django.db import migrations


# Logs whose rows gain MD5s: Malwarebytes and Fixlog File: blocks (pairs),
# Trojan Killer (MD5-only rows).
REBUILT_LOG_TYPES = ['Malwarebytes', 'Fixlog', 'Trojan Killer']


def rebuild_file_hashes(apps, schema_editor):
    """Re-extract the rows of those logs with their MD5s. Local parsing
    only (no centralbox call); a log that fails to parse keeps no rows."""
    from fixlist.file_hashes import extract_file_hashes

    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    UploadedLogFileHash = apps.get_model('fixlist', 'UploadedLogFileHash')
    queryset = UploadedLog.objects.filter(log_type__in=REBUILT_LOG_TYPES).only('id', 'log_type', 'content')
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
    """Separate from 0097: PostgreSQL cannot add 0097's indexes and rewrite
    the rows in one transaction."""

    dependencies = [
        ('fixlist', '0097_centralbox_md5'),
    ]

    operations = [
        migrations.RunPython(rebuild_file_hashes, migrations.RunPython.noop),
    ]
