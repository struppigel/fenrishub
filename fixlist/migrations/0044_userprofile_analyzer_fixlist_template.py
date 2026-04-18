from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0043_convert_startup_exact_rules_to_parsed'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='analyzer_fixlist_template',
            field=models.TextField(blank=True, default=''),
        ),
    ]
