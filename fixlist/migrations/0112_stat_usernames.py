from django.db import migrations, models

BATCH_SIZE = 500


def _backfill(source_model, stat_model, source_field, stat_field):
    """Copy each existing source row's name, keyed by stat_username, to its snapshot."""
    from fixlist.models import stat_username

    names = {pk: stat_username(name) for pk, name in source_model.objects.values_list('pk', source_field)}
    pks = sorted(names)
    for start in range(0, len(pks), BATCH_SIZE):
        chunk = pks[start:start + BATCH_SIZE]
        stats = list(stat_model.objects.filter(source_id__in=chunk).only('pk', 'source_id'))
        for stat in stats:
            setattr(stat, stat_field, names[stat.source_id])
        stat_model.objects.bulk_update(stats, [stat_field])


def backfill_stat_usernames(apps, schema_editor):
    """Fill the forum usernames of snapshots whose log or fixlist still exists
    (trashed ones too), keyed in Python by models.stat_username - the same key
    new snapshots get, whatever the database's TRIM / LOWER do. The rest stay ''."""
    _backfill(apps.get_model('fixlist', 'UploadedLog'), apps.get_model('fixlist', 'UploadedLogStat'),
              'forum_username', 'forum_username')
    _backfill(apps.get_model('fixlist', 'Fixlist'), apps.get_model('fixlist', 'FixlistStat'),
              'username', 'username')


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0111_stat_tag_resync'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedlogstat',
            name='forum_username',
            field=models.CharField(blank=True, db_index=True, default='', max_length=100),
        ),
        migrations.AddField(
            model_name='fixliststat',
            name='username',
            field=models.CharField(blank=True, db_index=True, default='', max_length=255),
        ),
        migrations.RunPython(backfill_stat_usernames, migrations.RunPython.noop),
    ]
