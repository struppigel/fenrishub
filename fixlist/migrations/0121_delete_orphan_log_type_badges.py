"""Delete custom log type badges that nothing uses.

Saving a log type detection rule created a badge for its log type, and
deleting the rule (or changing its log type) left the badge behind, so the
old name stayed in every log type list (e.g. a "test" type in the rule
editor). The views now clean up after themselves through
`delete_orphan_log_type_badges`; this removes the badges orphaned before that,
using the same test: not built-in, and no detection rule, upload (trashed
included) or statistics row with the name.
"""

from django.db import migrations


def delete_orphan_badges(apps, schema_editor):
    LogTypeBadge = apps.get_model('fixlist', 'LogTypeBadge')
    used = set()
    for model_name in ('LogTypeDetectionRule', 'UploadedLog', 'UploadedLogStat', 'AnalysisTiming'):
        model = apps.get_model('fixlist', model_name)
        used.update(model.objects.values_list('log_type', flat=True).distinct())
    LogTypeBadge.objects.filter(is_builtin=False).exclude(name__in=used).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0120_userprofile_force_private_rule_set'),
    ]

    operations = [
        migrations.RunPython(delete_orphan_badges, migrations.RunPython.noop),
    ]
