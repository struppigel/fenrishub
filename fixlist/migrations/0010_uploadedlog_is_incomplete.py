from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0009_uploadedlog_log_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedlog',
            name='is_incomplete',
            field=models.BooleanField(default=False),
        ),
    ]
