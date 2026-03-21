from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0006_classificationrule_owner'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UploadedLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('upload_id', models.CharField(db_index=True, max_length=48, unique=True)),
                ('reddit_username', models.CharField(db_index=True, max_length=20)),
                ('original_filename', models.CharField(max_length=255)),
                ('content', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'created_by',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='uploaded_logs',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
