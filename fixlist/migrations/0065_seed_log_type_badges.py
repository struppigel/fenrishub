from django.db import migrations


BUILTIN_BADGES = [
    ('FRST', '#8eb6d8'),
    ('Addition', '#d8b26e'),
    ('FRST&Addition', '#e8e8e8'),
    ('Fixlog', '#d38cff'),
    ('Shortcut', '#5eead4'),
    ('ESET', '#a3e635'),
    ('AdwCleaner', '#fb923c'),
    ('HitmanPro', '#ef4444'),
    ('Emsisoft', '#f472b6'),
    ('Malwarebytes', '#38bdf8'),
    ('Unknown', '#7a7a7a'),
]


def forwards(apps, schema_editor):
    LogTypeBadge = apps.get_model('fixlist', 'LogTypeBadge')
    for name, color in BUILTIN_BADGES:
        LogTypeBadge.objects.update_or_create(
            name=name, defaults={'color': color, 'is_builtin': True},
        )


def backwards(apps, schema_editor):
    LogTypeBadge = apps.get_model('fixlist', 'LogTypeBadge')
    LogTypeBadge.objects.filter(is_builtin=True).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0064_logtypebadge_and_freetext_log_type'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
