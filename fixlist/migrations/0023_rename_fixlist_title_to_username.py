from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0022_alter_classificationrule_status'),
    ]

    operations = [
        migrations.RenameField(
            model_name='fixlist',
            old_name='title',
            new_name='username',
        ),
    ]
