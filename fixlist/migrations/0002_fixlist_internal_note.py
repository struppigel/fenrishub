from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='fixlist',
            name='internal_note',
            field=models.TextField(blank=True),
        ),
    ]
