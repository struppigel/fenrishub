from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0012_uploadedlog_upload_id_max_length'),
    ]

    operations = [
        migrations.AddField(
            model_name='fixlist',
            name='deleted_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
    ]
