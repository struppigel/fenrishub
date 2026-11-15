from django.db import migrations
from django.db.models import Q

# The same as centralbox.PLACEHOLDER_LABELS (copied: migrations must not
# change when the module does).
PLACEHOLDERS = ('unknown', 'none', 'n/a', 'null')


def clear_placeholder_names(apps, schema_editor):
    """Stored families / malware types like "Unknown" are no names: clear them,
    so labels say "malicious" (new answers are stored without them)."""
    HashVerdict = apps.get_model('fixlist', 'HashVerdict')
    for field in ('family', 'malware_type'):
        query = Q()
        for name in PLACEHOLDERS:
            query |= Q(**{f'{field}__iexact': name})
        HashVerdict.objects.filter(query).update(**{field: ''})


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0103_fixlog_hitmanpro_hash_rows'),
    ]

    operations = [
        migrations.RunPython(clear_placeholder_names, migrations.RunPython.noop),
    ]
