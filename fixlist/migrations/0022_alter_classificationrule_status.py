from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0021_uploadedlog_recipient_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='classificationrule',
            name='status',
            field=models.CharField(
                choices=[
                    ('B', 'Malware'),
                    ('P', 'Potentially unwanted'),
                    ('C', 'Clean'),
                    ('!', 'Warning'),
                    ('A', 'Alert'),
                    ('G', 'Grayware'),
                    ('S', 'Security software'),
                    ('I', 'Informational'),
                    ('J', 'Junk'),
                    ('?', 'Unknown'),
                ],
                max_length=1,
            ),
        ),
    ]