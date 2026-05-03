import django.core.validators
from django.db import migrations, models
from django.db.models import Q


NEW_PRIORITY_BY_MATCH_TYPE = {
    'exact': 19,
    'parsed': 15,
    'filepath': 11,
    'substring': 7,
    'regex': 3,
}


def reset_priorities_to_new_defaults(apps, schema_editor):
    Rule = apps.get_model('fixlist', 'ClassificationRule')
    for match_type, priority in NEW_PRIORITY_BY_MATCH_TYPE.items():
        Rule.objects.filter(match_type=match_type).update(priority=priority)


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0049_classificationrule_priority'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='classificationrule',
            name='classificationrule_priority_range',
        ),
        migrations.RunPython(reset_priorities_to_new_defaults, reverse_code=migrations.RunPython.noop),
        migrations.AlterField(
            model_name='classificationrule',
            name='priority',
            field=models.PositiveSmallIntegerField(
                null=True,
                blank=True,
                db_index=True,
                help_text=(
                    '0-20; higher wins. Lower priorities are entirely shadowed. '
                    'Auto-set from match_type when blank.'
                ),
                validators=[
                    django.core.validators.MinValueValidator(0),
                    django.core.validators.MaxValueValidator(20),
                ],
            ),
        ),
        migrations.AddConstraint(
            model_name='classificationrule',
            constraint=models.CheckConstraint(
                check=Q(priority__gte=0) & Q(priority__lte=20),
                name='classificationrule_priority_range',
            ),
        ),
    ]
