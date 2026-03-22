from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0010_uploadedlog_is_incomplete'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedlog',
            name='deleted_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
    ]
