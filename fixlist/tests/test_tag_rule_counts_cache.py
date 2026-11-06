"""tag_rule_counts: cached per state of the rules, and exactly the old per-tag matching.

Test regexes are plain literals or simple alternations (linear time).
"""

from datetime import timedelta

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from .. import tagging
from ..models import ClassificationRule, RuleTag
from ..tagging import TagConditions, matching_rule_ids_by_tag, tag_rule_counts
from .factories import make_rule


def _reference_counts(tags):
    """The counts as tag_rule_counts computed them before caching: every tag on every rule."""
    active = {tag.pk: TagConditions.of(tag) for tag in tags if not TagConditions.of(tag).is_empty}
    pending = {tag.pk: 0 for tag in tags}
    unmatched = {tag.pk: 0 for tag in tags}
    tagged = set(
        ClassificationRule.tags.through.objects.filter(ruletag_id__in=active.keys())
        .values_list('classificationrule_id', 'ruletag_id')
    )
    matched = set()
    for rule in ClassificationRule.objects.all():
        for tag_pk, conditions in active.items():
            if conditions.matches_rule(rule):
                matched.add((rule.pk, tag_pk))
                if (rule.pk, tag_pk) not in tagged:
                    pending[tag_pk] += 1
    for _rule_pk, tag_pk in tagged - matched:
        unmatched[tag_pk] += 1
    return {tag.pk: (pending[tag.pk], unmatched[tag.pk]) for tag in tags}


def _scans_rules(queries):
    """Whether a captured query reads rule texts (the full scan)."""
    return any('"source_text"' in q['sql'] or '"description"' in q['sql'] for q in queries)


class RuleCountsTestBase(TestCase):
    def setUp(self):
        tagging.clear_rule_match_cache()
        self.addCleanup(tagging.clear_rule_match_cache)


class RuleCountsMatchReferenceTests(RuleCountsTestBase):
    def setUp(self):
        super().setUp()
        self.miner = make_rule('C:\\miner\\xmrig.exe', status='B', description='coin miner')
        self.pup = make_rule('C:\\tools\\toolbar.exe', status='P', description='ad toolbar')
        self.clean = make_rule('C:\\Windows\\explorer.exe', status='C', description='windows shell')
        self.runkey = make_rule(
            'HKLM\\Run: [miner] C:\\miner.exe', status='B', description='', entry_type='runkey',
        )
        self.tags = [
            RuleTag.objects.create(name='miner any', match_pattern='miner'),
            RuleTag.objects.create(name='miner source', match_pattern='miner', match_scope=RuleTag.SCOPE_SOURCE),
            RuleTag.objects.create(name='miner description', match_pattern='miner', match_scope=RuleTag.SCOPE_DESCRIPTION),
            RuleTag.objects.create(name='miner no runkey', match_pattern='miner', exclude_pattern='run:'),
            RuleTag.objects.create(name='B only', match_statuses=['B']),
            RuleTag.objects.create(name='runkeys', match_entry_types=['runkey']),
            RuleTag.objects.create(name='tool or shell', match_pattern='toolbar|shell', match_statuses=['P', 'C']),
            # Stored before validation caught it: neither engine path ever matches it.
            RuleTag.objects.create(name='lookahead', match_pattern='(?=x)y'),
            RuleTag.objects.create(name='empty'),
        ]
        self.tags[0].rules.add(self.miner, self.clean)  # clean no longer meets "miner"
        self.tags[4].rules.add(self.runkey)

    def test_counts_equal_the_per_tag_reference(self):
        self.assertEqual(tag_rule_counts(self.tags), _reference_counts(self.tags))

    def test_counts_for_any_subset_equal_the_reference(self):
        for start in range(len(self.tags)):
            page = self.tags[start:start + 3]
            self.assertEqual(tag_rule_counts(page), _reference_counts(page), [tag.name for tag in page])

    def test_matched_rules_per_scope(self):
        matched = matching_rule_ids_by_tag({tag.pk: TagConditions.of(tag) for tag in self.tags[:4]})
        self.assertEqual(matched[self.tags[0].pk], {self.miner.pk, self.runkey.pk})
        self.assertEqual(matched[self.tags[1].pk], {self.miner.pk, self.runkey.pk})
        self.assertEqual(matched[self.tags[2].pk], {self.miner.pk})
        self.assertEqual(matched[self.tags[3].pk], {self.miner.pk})


class RuleCountsCacheTests(RuleCountsTestBase):
    def setUp(self):
        super().setUp()
        self.rule = make_rule('C:\\miner\\xmrig.exe', status='B', description='coin miner')
        self.tag = RuleTag.objects.create(name='miner', match_pattern='miner')

    def test_second_call_does_not_rescan_the_rules(self):
        tag_rule_counts([self.tag])
        with CaptureQueriesContext(connection) as ctx:
            self.assertEqual(tag_rule_counts([self.tag]), {self.tag.pk: (1, 0)})
        self.assertFalse(_scans_rules(ctx.captured_queries))

    def test_tagging_a_rule_shows_at_once(self):
        self.assertEqual(tag_rule_counts([self.tag]), {self.tag.pk: (1, 0)})
        self.tag.rules.add(self.rule)
        self.assertEqual(tag_rule_counts([self.tag]), {self.tag.pk: (0, 0)})
        other = make_rule('C:\\clean.exe', status='C', description='clean')
        self.tag.rules.add(other)
        self.assertEqual(tag_rule_counts([self.tag]), {self.tag.pk: (0, 1)})

    def test_added_edited_and_deleted_rules_change_the_counts(self):
        tag_rule_counts([self.tag])
        second = make_rule('C:\\other\\miner2.exe', status='B')
        self.assertEqual(tag_rule_counts([self.tag]), {self.tag.pk: (2, 0)})
        second.description = 'renamed'
        second.source_text = 'C:\\other\\x.exe'
        second.save()
        self.assertEqual(tag_rule_counts([self.tag]), {self.tag.pk: (1, 0)})
        self.rule.delete()
        self.assertEqual(tag_rule_counts([self.tag]), {self.tag.pk: (0, 0)})

    def test_rule_change_in_another_process_is_noticed(self):
        tag_rule_counts([self.tag])
        # Another worker edits the rule: no signal fires here, only the table changes.
        ClassificationRule.objects.filter(pk=self.rule.pk).update(
            description='renamed', source_text='C:\\x.exe', updated_at=timezone.now() + timedelta(seconds=1),
        )
        self.assertEqual(tag_rule_counts([self.tag]), {self.tag.pk: (0, 0)})

    def test_edited_tag_conditions_are_matched_again(self):
        self.assertEqual(tag_rule_counts([self.tag]), {self.tag.pk: (1, 0)})
        self.tag.match_pattern = 'nothing like it'
        self.tag.save()
        self.assertEqual(tag_rule_counts([self.tag]), {self.tag.pk: (0, 0)})
