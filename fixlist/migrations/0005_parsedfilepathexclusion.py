from django.db import migrations, models


def seed_default_cmd_exclusion(apps, schema_editor):
    ParsedFilepathExclusion = apps.get_model('fixlist', 'ParsedFilepathExclusion')
    ParsedFilepathExclusion.objects.update_or_create(
        normalized_filepath=r'c:\windows\system32\cmd.exe',
        defaults={
            'note': 'Default parsed fallback exclusion to avoid cmd.exe noise.',
            'is_enabled': True,
        },
    )


def remove_default_cmd_exclusion(apps, schema_editor):
    ParsedFilepathExclusion = apps.get_model('fixlist', 'ParsedFilepathExclusion')
    ParsedFilepathExclusion.objects.filter(
        normalized_filepath=r'c:\windows\system32\cmd.exe'
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0004_classificationrule'),
    ]

    operations = [
        migrations.CreateModel(
            name='ParsedFilepathExclusion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('normalized_filepath', models.TextField(unique=True)),
                ('note', models.TextField(blank=True)),
                ('is_enabled', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['normalized_filepath'],
            },
        ),
        migrations.RunPython(seed_default_cmd_exclusion, remove_default_cmd_exclusion),
    ]
