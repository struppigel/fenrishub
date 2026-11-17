from django.db import migrations


def build_machine_signals(apps, schema_editor):
    """Store the machine signals of every log. Local parsing only; a log that
    fails to parse keeps no rows (the correlations then read its start)."""
    from fixlist.machine_signals import log_signals

    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    UploadedLogMachineSignal = apps.get_model('fixlist', 'UploadedLogMachineSignal')
    for upload in UploadedLog.objects.only('id', 'content').iterator(chunk_size=50):
        try:
            signals = log_signals(upload.content or '')
        except Exception:
            continue
        UploadedLogMachineSignal.objects.bulk_create([
            UploadedLogMachineSignal(upload_id=upload.id, kind=kind, value=value)
            for kind, values in signals.items() for value in sorted(values)
        ], batch_size=1000, ignore_conflicts=True)


class Migration(migrations.Migration):
    """Separate from 0107: PostgreSQL cannot add 0107's indexes and write
    the rows in one transaction."""

    dependencies = [
        ('fixlist', '0107_machine_signals'),
    ]

    operations = [
        migrations.RunPython(build_machine_signals, migrations.RunPython.noop),
    ]
