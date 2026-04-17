from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0041_userprofile_word_wrap'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='word_wrap',
            field=models.BooleanField(default=False),
        ),
    ]
