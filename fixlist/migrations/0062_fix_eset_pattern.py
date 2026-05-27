from django.db import migrations


NEW_ESET_PATTERN = (
    r'(Scanned files|Fichiers analys[eé]s|Archivos explorados|'
    r'Просканированные файлы|検査されたファイル)\s*:\s*\d'
)


def forwards(apps, schema_editor):
    LogTypeDetectionRule = apps.get_model('fixlist', 'LogTypeDetectionRule')
    rule = LogTypeDetectionRule.objects.filter(name='ESET scan report').first()
    if rule is None:
        return
    rule.pattern = NEW_ESET_PATTERN
    rule.scope = 'full'
    rule.save(update_fields=['pattern', 'scope', 'updated_at'])

    # Reclassify previously-Unknown logs that should now match.
    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    from fixlist.models import detect_log_type, _bump_logtype_rules_version
    _bump_logtype_rules_version()
    for log in UploadedLog.objects.filter(log_type='Unknown').only('id', 'content', 'log_type').iterator(chunk_size=200):
        new_type = detect_log_type(log.content or '')
        if new_type != log.log_type:
            log.log_type = new_type
            log.save(update_fields=['log_type', 'updated_at'])


def backwards(apps, schema_editor):
    pass  # No-op — keeps the improved pattern even on downgrade.


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0061_seed_log_type_rules_and_moderator_group'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
