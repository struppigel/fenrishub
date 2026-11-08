from django.db import migrations, models


def keep_existing_informational_regex_rules_whole_line(apps, schema_editor):
    """Regex rules now colour just the text they matched, like substring rules
    since 0074. Existing regex rules switch too -- except Informational (I)
    rules, which keep colouring the whole line. `update()` leaves `updated_at`
    alone, so the rules list's "recently edited" order is unaffected."""
    Rule = apps.get_model('fixlist', 'ClassificationRule')
    Rule.objects.filter(match_type='regex', status='I').update(color_whole_line=True)


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0089_infectioncase_reopened_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='classificationrule',
            name='color_whole_line',
            field=models.BooleanField(default=False, help_text='Substring, file path and regex rules only: colour the whole analyzer line instead of just the matched text.'),
        ),
        migrations.RunPython(
            keep_existing_informational_regex_rules_whole_line,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
