from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0040_rename_generic_category_lowercase'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='word_wrap',
            field=models.BooleanField(default=True),
        ),
    ]
