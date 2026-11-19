from django.db import migrations


def rebuild_spor_logs(apps, schema_editor):
    """Spor logs got a highlighter (list chips), FILES hash rows and header
    machine signals: fill them in for the uploads that already exist. Local
    parsing only (no centralbox call). Logs still typed Unknown get all of it
    when they are re-typed (on viewing, or with redetect_log_types)."""
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
        ('fixlist', '0108_machine_signals_rows'),
    ]

    operations = [
        migrations.RunPython(rebuild_spor_logs, migrations.RunPython.noop),
    ]
