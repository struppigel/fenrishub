from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0008_uploadedlog_stats'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedlog',
            name='log_type',
            field=models.CharField(
                choices=[
                    ('FRST', 'FRST'),
                    ('Addition', 'Addition'),
                    ('FRST&Addition', 'FRST&Addition'),
                    ('Fixlist', 'Fixlist'),
                    ('Unknown', 'Unknown'),
                ],
                default='Unknown',
                max_length=16,
            ),
        ),
    ]
