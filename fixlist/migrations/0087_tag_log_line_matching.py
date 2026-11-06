from django.db import migrations, models


class Migration(migrations.Migration):
    """Tags that also match log lines.

    No backfill: no tag matches log lines yet, and a cached analysis without
    stored line tags (None) gets them computed the first time it is read.
    """

    dependencies = [
        ('fixlist', '0086_uploadedlogstat_rule_ids'),
    ]

    operations = [
        migrations.AddField(
            model_name='ruletag',
            name='match_log_lines',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='uploadedloganalysis',
            name='line_tags',
            field=models.JSONField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='uploadedlogstat',
            name='line_tag_ids',
            field=models.JSONField(blank=True, default=None, null=True),
        ),
    ]
