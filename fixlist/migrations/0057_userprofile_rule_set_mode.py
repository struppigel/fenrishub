from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0056_uploadedloganalysis'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='rule_set_mode',
            field=models.CharField(
                choices=[('shared', 'Shared'), ('private', 'Private')],
                default='shared',
                max_length=16,
            ),
        ),
    ]
