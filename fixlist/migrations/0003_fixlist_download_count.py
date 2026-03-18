from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0002_fixlist_internal_note'),
    ]

    operations = [
        migrations.AddField(
            model_name='fixlist',
            name='download_count',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
