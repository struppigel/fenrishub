from django.db import migrations


def rebuild_spor_logs(apps, schema_editor):
    """Spor logs write details for linking with FRST logs: the files' MD5 next
    to their SHA256 (hash rows with both, so MD5-only rows of other logs find
    the SHA256's verdict) and the Machine SID (a machine signal). Rebuild the
    hash rows, stats and machine signals of the Spor uploads that exist.
    Local parsing only (no centralbox call)."""
    from fixlist.file_hashes import extract_file_hashes
    from fixlist.log_highlighting import compute_tool_stats
    from fixlist.machine_signals import log_signals

    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    UploadedLogFileHash = apps.get_model('fixlist', 'UploadedLogFileHash')
    UploadedLogMachineSignal = apps.get_model('fixlist', 'UploadedLogMachineSignal')
    queryset = UploadedLog.objects.filter(log_type='Spor').only('id', 'log_type', 'content', 'deleted_at')
    for upload in queryset.iterator(chunk_size=10):
        content = upload.content or ''
        # bulk_update leaves updated_at alone.
        upload.tool_stats = compute_tool_stats(upload.log_type, content)
        UploadedLog.objects.bulk_update([upload], ['tool_stats'])
        rows = extract_file_hashes(upload.log_type, content)
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
        if upload.deleted_at is not None:
            continue
        try:
            signals = log_signals(content)
        except Exception:
            continue
        UploadedLogMachineSignal.objects.filter(upload_id=upload.id).delete()
        UploadedLogMachineSignal.objects.bulk_create([
            UploadedLogMachineSignal(upload_id=upload.id, kind=kind, value=value)
            for kind, values in signals.items() for value in sorted(values)
        ], batch_size=1000, ignore_conflicts=True)


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0109_spor_rows'),
    ]

    operations = [
        migrations.RunPython(rebuild_spor_logs, migrations.RunPython.noop),
    ]
