from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion

import fixlist.models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0005_parsedfilepathexclusion'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='classificationrule',
            name='owner',
            field=models.ForeignKey(
                default=fixlist.models.get_default_rule_owner_id,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='classification_rules',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AlterUniqueTogether(
            name='classificationrule',
            unique_together={('owner', 'status', 'match_type', 'source_text')},
        ),
    ]
