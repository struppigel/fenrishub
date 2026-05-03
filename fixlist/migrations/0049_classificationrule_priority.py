import django.core.validators
from django.db import migrations, models
from django.db.models import Q


PRIORITY_BY_MATCH_TYPE = {
    'exact': 20,
    'parsed': 10,
    'filepath': 8,
    'substring': 5,
    'regex': 2,
}


def backfill_priority(apps, schema_editor):
    Rule = apps.get_model('fixlist', 'ClassificationRule')
    for match_type, priority in PRIORITY_BY_MATCH_TYPE.items():
        Rule.objects.filter(match_type=match_type).update(priority=priority)


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0048_backfill_stats'),
    ]

    operations = [
        migrations.AddField(
            model_name='classificationrule',
            name='priority',
            field=models.PositiveSmallIntegerField(
                null=True,
                blank=True,
                db_index=True,
                help_text=(
                    '0-25; higher wins. Lower priorities are entirely shadowed. '
                    'Auto-set from match_type when blank.'
                ),
                validators=[
                    django.core.validators.MinValueValidator(0),
                    django.core.validators.MaxValueValidator(25),
                ],
            ),
        ),
        migrations.RunPython(backfill_priority, reverse_code=migrations.RunPython.noop),
        migrations.AlterModelOptions(
            name='classificationrule',
            options={'ordering': ['-priority', 'status', 'match_type', 'source_text']},
        ),
        migrations.AddConstraint(
            model_name='classificationrule',
            constraint=models.CheckConstraint(
                check=Q(priority__gte=0) & Q(priority__lte=25),
                name='classificationrule_priority_range',
            ),
        ),
    ]
