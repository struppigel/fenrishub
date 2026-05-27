from django.db import migrations


UPDATES = [
    # The German Addition header "Zusätzliches Untersuchungsergebnis..." contains the
    # German FRST header as a substring, which caused Addition logs to be misclassified
    # as FRST&Addition. Anchor the FRST pattern at the start of the (lstripped) content.
    ('FRST (German)', r'^Untersuchungsergebnis von Farbar Recovery Scan Tool', 'start'),
    # Same problem for Dutch: "Extra scanresultaten van..." contains "scanresultaten van...".
    ('FRST (Dutch)', r'(?im)^Scanresultaten van Farbar Recovery Scan Tool', 'start'),
]


def forwards(apps, schema_editor):
    LogTypeDetectionRule = apps.get_model('fixlist', 'LogTypeDetectionRule')
    for name, pattern, scope in UPDATES:
        rule = LogTypeDetectionRule.objects.filter(name=name).first()
        if rule is None:
            continue
        rule.pattern = pattern
        rule.scope = scope
        rule.save(update_fields=['pattern', 'scope', 'updated_at'])

    # Reclassify any logs that were wrongly tagged FRST&Addition because of the bug.
    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    from fixlist.models import detect_log_type, _bump_logtype_rules_version
    _bump_logtype_rules_version()
    affected = UploadedLog.objects.filter(log_type__in=['FRST&Addition', 'FRST', 'Addition'])
    for log in affected.only('id', 'content', 'log_type').iterator(chunk_size=200):
        new_type = detect_log_type(log.content or '')
        if new_type != log.log_type:
            log.log_type = new_type
            log.save(update_fields=['log_type', 'updated_at'])


def backwards(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0062_fix_eset_pattern'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
