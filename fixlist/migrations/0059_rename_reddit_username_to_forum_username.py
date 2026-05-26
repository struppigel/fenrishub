from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0058_uploadedloganalysis_rule_set_key'),
    ]

    operations = [
        migrations.RenameField(
            model_name='uploadedlog',
            old_name='reddit_username',
            new_name='forum_username',
        ),
        migrations.AlterField(
            model_name='uploadedlog',
            name='forum_username',
            field=models.CharField(db_index=True, max_length=100),
        ),
    ]
