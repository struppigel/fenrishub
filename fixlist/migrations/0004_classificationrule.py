from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0003_fixlist_download_count'),
    ]

    operations = [
        migrations.CreateModel(
            name='ClassificationRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('B', 'Userdefined malware'), ('P', 'Userdefined potentially unwanted'), ('C', 'Userdefined clean entries'), ('!', 'Userdefined warning'), ('G', 'Userdefined grayware'), ('S', 'Userdefined security software'), ('I', 'Userdefined informational'), ('J', 'Userdefined junk'), ('?', 'Unknown')], max_length=1)),
                ('match_type', models.CharField(choices=[('exact', 'Exact line'), ('substring', 'Substring'), ('regex', 'Regex'), ('filepath', 'File path'), ('parsed', 'Parsed FRST entry')], max_length=16)),
                ('source_text', models.TextField(help_text='Rule input without description metadata.')),
                ('description', models.TextField(blank=True)),
                ('source_name', models.CharField(blank=True, max_length=128)),
                ('is_enabled', models.BooleanField(default=True)),
                ('entry_type', models.CharField(blank=True, max_length=64)),
                ('clsid', models.CharField(blank=True, max_length=128)),
                ('name', models.CharField(blank=True, max_length=512)),
                ('filepath', models.TextField(blank=True)),
                ('normalized_filepath', models.TextField(blank=True)),
                ('filename', models.CharField(blank=True, max_length=260)),
                ('company', models.CharField(blank=True, max_length=512)),
                ('arguments', models.TextField(blank=True)),
                ('file_not_signed', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['status', 'match_type', 'source_text'],
                'unique_together': {('status', 'match_type', 'source_text')},
            },
        ),
    ]
