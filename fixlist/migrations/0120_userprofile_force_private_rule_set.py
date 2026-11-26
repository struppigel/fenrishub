from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0119_analysis_timing'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='force_private_rule_set',
            field=models.BooleanField(
                default=False,
                help_text=(
                    'Training mode: the helper is locked to their own private rule set and sees no other '
                    "helpers' rules or verdicts. Only superusers can change this."
                ),
            ),
        ),
    ]
