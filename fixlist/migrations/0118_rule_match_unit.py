"""Rules match a line or a block (ClassificationRule.match_unit), replacing
apply_to_block ("match a line, give the verdict to its block").

A rule with apply_to_block becomes a block rule, matching the same blocks:

- substring rules: a text in one of the block's lines is in the block's text.
- regex rules run over the block's lines joined by line breaks, `^` / `$`
  per line. A pattern that can match a line break (`\\s`, `[^...]`, `\\W`,
  `\\D`) could now span two lines; those rules are printed for a look.
- exact rules: a block exact rule compares the whole block, so each becomes
  the block regex `^<the line>$`, which matches a block holding that line,
  as before. Its priority is kept.
- script rules always test lines, so they stay line rules (printed).
"""

import re

from django.db import migrations, models

# Regex parts that can match a line break.
_CROSSES_LINES_RE = re.compile(r'\\[sWD]|\[\^')


def exact_as_block_regex(text):
    """The block regex that matches a block holding the line `text`."""
    return '^' + re.escape(text.strip()) + '$'


def regex_may_cross_lines(pattern):
    return bool(_CROSSES_LINES_RE.search(pattern or ''))


def rules_to_migrate(rows):
    """(pks of the rules that become block rules, the exact ones among them as
    (pk, owner_id, source_text)) of `rows`: (pk, owner_id, match_type,
    source_text, whole_log, apply_to_block) tuples."""
    block_pks, exact_rows = [], []
    for pk, owner_id, match_type, source_text, whole_log, apply_to_block in rows:
        # Script rules always test lines (a block rule cannot be a script), so
        # they stay line rules; forwards() prints them.
        if not apply_to_block or whole_log or match_type == 'script':
            continue
        block_pks.append(pk)
        if match_type == 'exact':
            exact_rows.append((pk, owner_id, source_text))
    return block_pks, exact_rows


def forwards(apps, schema_editor):
    rule_model = apps.get_model('fixlist', 'ClassificationRule')
    rows = list(rule_model.objects.filter(apply_to_block=True).values_list(
        'pk', 'owner_id', 'match_type', 'source_text', 'whole_log', 'apply_to_block',
    ))
    block_pks, exact_rows = rules_to_migrate(rows)
    if block_pks:
        rule_model.objects.filter(pk__in=block_pks).update(match_unit='block')
    for pk, owner_id, source_text in exact_rows:
        rule = rule_model.objects.get(pk=pk)
        pattern = exact_as_block_regex(source_text)
        twin = rule_model.objects.filter(
            owner_id=owner_id, status=rule.status, match_type='regex', source_text=pattern,
            whole_log=False, condition_key=rule.condition_key, match_unit='block',
        ).exclude(pk=pk).exists()
        if twin:
            print(f'\n  block rule #{pk} (exact) left as it is, its regex exists already: {source_text[:80]!r}')
            continue
        rule_model.objects.filter(pk=pk).update(match_type='regex', source_text=pattern)
    for pk, _owner_id, match_type, source_text, whole_log, _flag in rows:
        if pk in block_pks and match_type == 'regex' and regex_may_cross_lines(source_text):
            print(f'\n  block rule #{pk}: its regex may now match across lines, check it: {source_text[:80]!r}')
        if match_type == 'script' and not whole_log:
            print(f'\n  script rule #{pk} stays a line rule, its verdict no longer goes to its block: {source_text[:80]!r}')


def backwards(apps, schema_editor):
    rule_model = apps.get_model('fixlist', 'ClassificationRule')
    rule_model.objects.filter(match_unit='block').update(apply_to_block=True)


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0117_rule_only_entry_types'),
    ]

    operations = [
        migrations.AddField(
            model_name='classificationrule',
            name='match_unit',
            field=models.CharField(
                choices=[('line', 'line'), ('block', 'block')], default='line', max_length=8,
                help_text='Per-line rules only: test one line, or the whole block (its verdict goes to every line of the block).',
            ),
        ),
        migrations.AlterUniqueTogether(
            name='classificationrule',
            unique_together={('owner', 'status', 'match_type', 'source_text', 'whole_log', 'condition_key', 'match_unit')},
        ),
        migrations.RunPython(forwards, backwards),
        migrations.RemoveField(
            model_name='classificationrule',
            name='apply_to_block',
        ),
    ]
