from django.db import migrations


BUILTIN_RULES = [
    # FRST main scan (priority 10) — header markers in many languages
    ('FRST (English)', 'FRST', r'Scan result of Farbar Recovery Scan Tool', 'full', 10),
    ('FRST (German)', 'FRST', r'^Untersuchungsergebnis von Farbar Recovery Scan Tool', 'start', 10),
    ('FRST (Spanish)', 'FRST', r'Resultado del an[aá]lisis realizado por Farbar Recovery Scan Tool', 'full', 10),
    ('FRST (French)', 'FRST', r"R[eé]sultats d'analyse de\s+Farbar Recovery Scan Tool", 'full', 10),
    ('FRST (Polish)', 'FRST', r'Rezultaty skanowania Farbar Recovery Scan Tool', 'full', 10),
    ('FRST (Dutch)', 'FRST', r'(?im)^Scanresultaten van Farbar Recovery Scan Tool', 'start', 10),
    ('FRST (Portuguese)', 'FRST', r'Resultado do an[aá]lise da Farbar Recovery Scan Tool', 'full', 10),
    ('FRST (Chinese)', 'FRST', r'Farbar Recovery Scan Tool \(FRST\).{0,40}版本', 'full', 10),
    ('FRST (Russian)', 'FRST', r'Результат сканирования Farbar Recovery Scan Tool', 'full', 10),

    # Addition.txt (priority 10)
    ('Addition (English)', 'Addition', r'Additional scan result of Farbar Recovery Scan Tool', 'full', 10),
    ('Addition (German)', 'Addition', r'Zus[aä]tzliches Untersuchungsergebnis von Farbar Recovery Scan Tool', 'full', 10),
    ('Addition (Spanish)', 'Addition', r'Resultados del An[aá]lisis Adicional de Farbar Recovery Scan Tool', 'full', 10),
    ('Addition (French)', 'Addition', r"R[eé]sultats de l'Analyse suppl[eé]mentaire de Farbar Recovery Scan Tool", 'full', 10),
    ('Addition (Polish)', 'Addition', r'Rezultaty skanu uzupe[lł]niaj[aą]cego Farbar Recovery Scan Tool', 'full', 10),
    ('Addition (Dutch)', 'Addition', r'Extra scanresultaten van Farbar Recovery Scan Tool', 'full', 10),
    ('Addition (Portuguese)', 'Addition', r'Resultado da an[aá]lise adicional Farbar Recovery Scan Tool', 'full', 10),
    ('Addition (Chinese)', 'Addition', r'额外的扫描结果 Farbar Recovery Scan Tool', 'full', 10),

    # Fixlog (priority 10)
    ('Fixlog (English)', 'Fixlog', r'^Fix result of Farbar Recovery Scan Tool', 'start', 10),

    # FRST Shortcut.txt variant scan (priority 20 — runs before generic third-party)
    ('FRST Shortcut.txt', 'Shortcut', r'^Users shortcut scan result \(x64\) Version:', 'start', 20),

    # Third-party AV tools (priority 50 — detection only, no analyzer support)
    ('Malwarebytes AdwCleaner', 'AdwCleaner', r'# Malwarebytes AdwCleaner \d', 'start', 50),
    ('HitmanPro', 'HitmanPro', r'HitmanPro \d+\.\d+\.\d+', 'start', 50),
    ('Emsisoft Emergency Kit', 'Emsisoft', r'^Emsisoft Emergency Kit - Version', 'start', 50),
    ('Malwarebytes Threat Scan', 'Malwarebytes', r'^Malwarebytes\s*\r?\nwww\.malwarebytes\.com', 'start', 50),
    # ESET scan reports — match the locale-specific counter keyword followed by a digit.
    # Each ESET log has a "Scanned files: N" line (or its localized equivalent).
    (
        'ESET scan report',
        'ESET',
        r'(Scanned files|Fichiers analys[eé]s|Archivos explorados|Просканированные файлы|検査されたファイル)\s*:\s*\d',
        'full',
        50,
    ),
]


def seed(apps, schema_editor):
    LogTypeDetectionRule = apps.get_model('fixlist', 'LogTypeDetectionRule')
    Group = apps.get_model('auth', 'Group')

    for name, log_type, pattern, scope, priority in BUILTIN_RULES:
        LogTypeDetectionRule.objects.update_or_create(
            name=name,
            defaults={
                'log_type': log_type,
                'pattern': pattern,
                'scope': scope,
                'priority': priority,
                'is_enabled': True,
                'is_builtin': True,
            },
        )

    Group.objects.get_or_create(name='moderator')

    # Reclassify existing logs cheaply — only the log_type label, not the
    # analyzer stats. Stats can be rebuilt afterwards with:
    #   python manage.py redetect_log_types --rebuild-stats
    UploadedLog = apps.get_model('fixlist', 'UploadedLog')
    from fixlist.models import detect_log_type, _bump_logtype_rules_version
    _bump_logtype_rules_version()
    for log in UploadedLog.objects.only('id', 'content', 'log_type').iterator(chunk_size=200):
        new_type = detect_log_type(log.content or '')
        if new_type != log.log_type:
            log.log_type = new_type
            log.save(update_fields=['log_type', 'updated_at'])


def unseed(apps, schema_editor):
    LogTypeDetectionRule = apps.get_model('fixlist', 'LogTypeDetectionRule')
    LogTypeDetectionRule.objects.filter(is_builtin=True).delete()
    Group = apps.get_model('auth', 'Group')
    Group.objects.filter(name='moderator').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0060_logtypedetectionrule_and_expand_choices'),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
