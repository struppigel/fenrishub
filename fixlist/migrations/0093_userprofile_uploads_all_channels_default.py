from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0092_recount_fixlog_stats'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='uploads_all_channels_default',
            field=models.BooleanField(default=False),
        ),
    ]
