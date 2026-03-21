from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0007_uploadedlog'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedlog',
            name='count_clean',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='uploadedlog',
            name='count_grayware',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='uploadedlog',
            name='count_info',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='uploadedlog',
            name='count_junk',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='uploadedlog',
            name='count_malware',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='uploadedlog',
            name='count_pup',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='uploadedlog',
            name='count_security',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='uploadedlog',
            name='count_unknown',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='uploadedlog',
            name='count_warning',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='uploadedlog',
            name='total_line_count',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
