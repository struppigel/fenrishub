"""Facts through the token API (version 6): reading facts and the facts found
in an analysis, writing facts and fact rules, and the rule options that came
with them (conditions on facts, parsed-type restrictions, block verdicts) on
rule read / write, the dry run and rule matching. Additive: requests without
the new fields keep their old meaning, so older MCP clients keep working."""

from ..analyzer import analyze_log_text
from ..fact_service import ConditionSpec, condition_key_for, set_rule_conditions
from ..models import ClassificationRule, Fact, FactRule, FactTagSource, RuleCondition, RuleTag
from ..rule_sets import resolve_user_rule_set_key
from ..upload_utils import store_cached_analysis
from ..views.api_auth import API_VERSION_HEADER
from .factories import make_uploaded_log
from .test_llm_api_write import ApiWriteBase

B, C = ClassificationRule.STATUS_MALWARE, ClassificationRule.STATUS_CLEAN
REQUIRE, FORBID = RuleCondition.POLARITY_REQUIRE, RuleCondition.POLARITY_FORBID
LOG, BLOCK = RuleCondition.SCOPE_LOG, RuleCondition.SCOPE_BLOCK

NVIDIA = r"R2 nvlddmkm; C:\Windows\System32\DriverStore\nvlddmkm.sys [1 2026-01-01] (NVIDIA Corporation)"
TARGET = r"HKLM\...\Run: [Updater] => C:\Users\a\AppData\Roaming\upd.exe [123 2026-01-01] () [File not signed]"
WITH_NVIDIA = "\n".join([NVIDIA, "", TARGET])


class FactApiBase(ApiWriteBase):
    def setUp(self):
        super().setUp()
        self.fact = Fact.objects.create(name='nvidia installed', description='the NVIDIA driver is there')
        self.fact_rule = FactRule.objects.create(
            owner=self.helper, fact=self.fact, match_type='substring', source_text='NVIDIA Corporation',
        )

    def conditional_rule(self, source_text, status=B, specs=None, owner=None):
        specs = specs if specs is not None else [ConditionSpec(self.fact.pk, FORBID, LOG)]
        rule = ClassificationRule.objects.create(
            owner=owner or self.admin, status=status, match_type='substring', source_text=source_text,
            condition_key=condition_key_for(specs),
        )
        set_rule_conditions(rule, specs)
        return rule


class FactReadTests(FactApiBase):
    def test_list_facts_with_counts(self):
        self.conditional_rule('upd.exe')
        response = self.get('api_v1_facts')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(int(response[API_VERSION_HEADER]), 6)
        [row] = response.json()['facts']
        self.assertEqual(
            {key: row[key] for key in ('fact_id', 'name', 'fact_rule_count', 'tag_source_count', 'conditional_rule_count')},
            {'fact_id': self.fact.pk, 'name': 'nvidia installed', 'fact_rule_count': 1,
             'tag_source_count': 0, 'conditional_rule_count': 1},
        )

    def test_list_facts_query(self):
        Fact.objects.create(name='kaspersky installed')
        names = [row['name'] for row in self.get('api_v1_facts', data={'q': 'kasper'}).json()['facts']]
        self.assertEqual(names, ['kaspersky installed'])

    def test_fact_detail(self):
        tag = RuleTag.objects.create(name='NVIDIA')
        FactTagSource.objects.create(fact=self.fact, tag=tag, statuses=['C'], mode=FactTagSource.MODE_DECIDED)
        rule = self.conditional_rule('upd.exe')
        body = self.get('api_v1_fact', self.fact.pk).json()
        self.assertEqual(body['tag_sources'], [{
            'tag_id': tag.pk, 'tag': 'NVIDIA', 'statuses': ['C'], 'mode': 'decided',
            'include_filepath_fallback': False,
        }])
        [fact_rule] = body['fact_rules']
        self.assertEqual((fact_rule['fact_rule_id'], fact_rule['owner']), (self.fact_rule.pk, 'alice'))
        [conditional] = body['conditional_rules']
        self.assertEqual((conditional['rule_id'], conditional['polarity'], conditional['scope']), (rule.pk, 'forbid', 'log'))

    def test_unknown_fact_is_404(self):
        self.assertEqual(self.get('api_v1_fact', 9999).status_code, 404)

    def test_analysis_lists_the_facts_found_with_line_numbers(self):
        make_uploaded_log('amber-falcon', content=WITH_NVIDIA, log_type='FRST&Addition')
        body = self.get('api_v1_upload_analysis', 'amber-falcon').json()
        self.assertEqual(body['facts'], [{
            'fact_id': self.fact.pk, 'name': 'nvidia installed', 'description': 'the NVIDIA driver is there',
            'lines': [1], 'whole_log': False,
        }])

    def test_analysis_without_summary_leaves_facts_out(self):
        make_uploaded_log('amber-falcon', content=WITH_NVIDIA, log_type='FRST&Addition')
        body = self.get('api_v1_upload_analysis', 'amber-falcon', data={'summary': '0'}).json()
        self.assertNotIn('facts', body)


class RuleOptionReadTests(FactApiBase):
    def test_rule_detail_and_list_show_the_new_options(self):
        rule = self.conditional_rule('upd.exe')
        ClassificationRule.objects.filter(pk=rule.pk).update(apply_to_block=True, only_entry_types=['runkey'])
        detail = self.get('api_v1_rule', rule.pk).json()
        self.assertEqual(detail['conditions'], [
            {'fact_id': self.fact.pk, 'fact': 'nvidia installed', 'polarity': 'forbid', 'scope': 'log'},
        ])
        self.assertTrue(detail['conditional'])
        self.assertTrue(detail['apply_to_block'])
        self.assertEqual(detail['only_entry_types'], ['runkey'])
        [row] = self.get('api_v1_rules').json()['rules']
        self.assertTrue(row['conditional'])
        self.assertNotIn('conditions', row)

    def test_plain_rule_has_no_conditions(self):
        rule = ClassificationRule.objects.create(owner=self.admin, status=B, match_type='exact', source_text='x')
        detail = self.get('api_v1_rule', rule.pk).json()
        self.assertEqual((detail['conditions'], detail['conditional']), ([], False))

    def test_match_rules_lists_conditional_rules_apart(self):
        rule = self.conditional_rule('upd.exe')
        body = self.post('api_v1_rule_match', body={'lines': [TARGET]}, raw=self.helper_raw).json()
        [result] = body['results']
        self.assertEqual(result['status'], '?')
        [conditional] = result['conditional']
        self.assertEqual(conditional['rule_id'], rule.pk)
        self.assertEqual(conditional['conditions'], [{'fact': 'nvidia installed', 'polarity': 'forbid', 'scope': 'log'}])

    def test_match_rules_without_conditional_rules_keeps_its_shape(self):
        ClassificationRule.objects.create(owner=self.admin, status=B, match_type='substring', source_text='upd.exe')
        [result] = self.post('api_v1_rule_match', body={'lines': [TARGET]}, raw=self.helper_raw).json()['results']
        self.assertNotIn('conditional', result)


class RuleConditionWriteTests(FactApiBase):
    def create(self, **fields):
        return self.post('api_v1_rule_create', body={'status': B, 'match_type': 'substring', 'source_text': 'upd.exe', **fields})

    def test_create_with_conditions_by_id_and_name(self):
        other = Fact.objects.create(name='Roaming run key')
        response = self.create(conditions=[
            {'fact_id': self.fact.pk, 'polarity': 'forbid'},
            {'fact': 'roaming RUN key', 'polarity': 'require', 'scope': 'block'},
        ])
        self.assertEqual(response.status_code, 201, response.content)
        [created] = response.json()['created']
        self.assertEqual(
            sorted((c['fact'], c['polarity'], c['scope']) for c in created['conditions']),
            [('Roaming run key', 'require', 'block'), ('nvidia installed', 'forbid', 'log')],
        )
        rule = ClassificationRule.objects.get(pk=created['rule_id'])
        self.assertEqual(rule.condition_key, condition_key_for([
            ConditionSpec(self.fact.pk, FORBID, LOG), ConditionSpec(other.pk, REQUIRE, BLOCK),
        ]))

    def test_unknown_fact_creates_nothing(self):
        response = self.create(conditions=[{'fact': 'nope'}])
        self.assertEqual(response.status_code, 400)
        self.assertIn('Unknown fact', response.json()['error'])
        self.assertFalse(ClassificationRule.objects.exists())

    def test_bad_polarity_is_refused(self):
        response = self.create(conditions=[{'fact_id': self.fact.pk, 'polarity': 'maybe'}])
        self.assertEqual(response.status_code, 400)

    def test_conditional_twin_of_a_plain_rule_is_allowed_but_not_a_second_copy(self):
        self.assertEqual(self.create().status_code, 201)
        conditions = [{'fact_id': self.fact.pk, 'polarity': 'forbid'}]
        self.assertEqual(self.create(conditions=conditions).status_code, 201)
        self.assertEqual(self.create(conditions=conditions).status_code, 409)
        self.assertEqual(ClassificationRule.objects.count(), 2)

    def test_create_with_entry_types_and_block_verdict(self):
        response = self.create(only_entry_types=['runkey'], apply_to_block=True)
        self.assertEqual(response.status_code, 201, response.content)
        [created] = response.json()['created']
        self.assertEqual((created['only_entry_types'], created['apply_to_block']), (['runkey'], True))

    def test_unknown_entry_type_is_refused(self):
        response = self.create(only_entry_types=['nonsense'])
        self.assertEqual(response.status_code, 400)
        self.assertIn('only_entry_types', response.json()['error'])

    def test_update_keeps_conditions_when_left_out_and_clears_them_with_an_empty_list(self):
        rule = self.conditional_rule('upd.exe')
        response = self.post('api_v1_rule_update', rule.pk, body={'description': 'changed'})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(len(response.json()['conditions']), 1)
        response = self.post('api_v1_rule_update', rule.pk, body={'conditions': []})
        self.assertEqual(response.json()['conditions'], [])
        rule.refresh_from_db()
        self.assertEqual(rule.condition_key, '')
        self.assertFalse(RuleCondition.objects.filter(rule=rule).exists())

    def test_update_sets_conditions_and_entry_types(self):
        rule = ClassificationRule.objects.create(owner=self.helper, status=B, match_type='substring', source_text='upd.exe')
        response = self.post('api_v1_rule_update', rule.pk, body={
            'conditions': [{'fact': 'nvidia installed', 'polarity': 'require'}], 'only_entry_types': ['runkey'],
            'apply_to_block': True,
        })
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body['owner'], 'alice')
        self.assertEqual(body['conditions'][0]['polarity'], 'require')
        self.assertEqual((body['only_entry_types'], body['apply_to_block']), (['runkey'], True))

    def test_whole_log_rule_conditions_must_look_at_the_log(self):
        response = self.post('api_v1_rule_create', body={
            'status': 'A', 'match_type': 'regex', 'source_text': 'upd[.]exe', 'whole_log': True,
            'conditions': [{'fact_id': self.fact.pk, 'scope': 'block'}],
        })
        self.assertEqual(response.status_code, 400)


class FactWriteTests(FactApiBase):
    def test_create_fact_with_tag_sources_by_name(self):
        tag = RuleTag.objects.create(name='Kaspersky')
        response = self.post('api_v1_fact_create', body={
            'name': 'Kaspersky installed', 'description': 'AV present',
            'tag_sources': [{'tag': 'kaspersky', 'statuses': ['S', 'C'], 'mode': 'decided'}],
        })
        self.assertEqual(response.status_code, 201, response.content)
        fact = Fact.objects.get(name='Kaspersky installed')
        source = fact.tag_sources.get()
        self.assertEqual((source.tag, source.statuses, source.mode), (tag, ['C', 'S'], 'decided'))
        self.assertEqual(fact.created_by, self.admin)

    def test_name_clash_is_409(self):
        response = self.post('api_v1_fact_create', body={'name': 'NVIDIA INSTALLED'})
        self.assertEqual(response.status_code, 409)

    def test_update_keeps_tag_sources_when_left_out(self):
        tag = RuleTag.objects.create(name='NVIDIA')
        FactTagSource.objects.create(fact=self.fact, tag=tag)
        response = self.post('api_v1_fact_update', self.fact.pk, body={'name': 'nvidia driver installed'})
        self.assertEqual(response.status_code, 200, response.content)
        self.fact.refresh_from_db()
        self.assertEqual(self.fact.name, 'nvidia driver installed')
        self.assertEqual(self.fact.description, 'the NVIDIA driver is there')
        self.assertTrue(self.fact.tag_sources.exists())
        self.post('api_v1_fact_update', self.fact.pk, body={'tag_sources': []})
        self.assertFalse(self.fact.tag_sources.exists())

    def test_unknown_tag_in_a_source_is_refused(self):
        response = self.post('api_v1_fact_update', self.fact.pk, body={'tag_sources': [{'tag_id': 9999}]})
        self.assertEqual(response.status_code, 400)

    def test_create_fact_rules_for_a_new_fact_by_name(self):
        response = self.post('api_v1_fact_rule_create', body={
            'fact': 'Avira installed', 'match_type': 'substring', 'source_text': 'Avira\nAntivir',
            'only_entry_types': ['service'],
        })
        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        self.assertEqual(body['fact']['name'], 'Avira installed')
        self.assertEqual(sorted(row['source_text'] for row in body['created']), ['Antivir', 'Avira'])
        self.assertEqual(body['created'][0]['only_entry_types'], ['service'])
        self.assertEqual(FactRule.objects.filter(fact__name='Avira installed', owner=self.admin).count(), 2)

    def test_existing_fact_by_name_is_reused_and_duplicates_skipped(self):
        body = {'fact': 'NVIDIA installed', 'match_type': 'substring', 'source_text': 'nvlddmkm'}
        self.assertEqual(self.post('api_v1_fact_rule_create', body=body).status_code, 201)
        self.assertEqual(Fact.objects.count(), 1)
        self.assertEqual(self.post('api_v1_fact_rule_create', body=body).status_code, 409)

    def test_fact_rule_needs_a_fact(self):
        response = self.post('api_v1_fact_rule_create', body={'match_type': 'substring', 'source_text': 'x'})
        self.assertEqual(response.status_code, 400)

    def test_whole_log_fact_rule_must_be_regex_or_script(self):
        response = self.post('api_v1_fact_rule_create', body={
            'fact_id': self.fact.pk, 'match_type': 'substring', 'source_text': 'x', 'whole_log': True,
        })
        self.assertEqual(response.status_code, 400)

    def test_update_fact_rule_of_another_helper(self):
        response = self.post('api_v1_fact_rule_update', self.fact_rule.pk, body={
            'source_text': 'NVIDIA Corp', 'is_enabled': False,
        })
        self.assertEqual(response.status_code, 200, response.content)
        self.fact_rule.refresh_from_db()
        self.assertEqual((self.fact_rule.source_text, self.fact_rule.is_enabled), ('NVIDIA Corp', False))
        self.assertEqual(self.fact_rule.owner, self.helper)

    def test_update_fact_rule_moves_it_to_another_fact(self):
        other = Fact.objects.create(name='GPU present')
        response = self.post('api_v1_fact_rule_update', self.fact_rule.pk, body={'fact_id': other.pk})
        self.assertEqual(response.json()['fact'], 'GPU present')

    def test_read_token_cannot_write_facts(self):
        response = self.post('api_v1_fact_create', body={'name': 'x'}, raw=self.helper_raw)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Fact.objects.filter(name='x').exists())


class RuleTestWithFactsTests(FactApiBase):
    def stored(self, upload_id, content, analyze=True):
        log = make_uploaded_log(upload_id, content=content, log_type='FRST&Addition')
        if analyze:
            key = resolve_user_rule_set_key(self.helper)
            store_cached_analysis(log, key, analyze_log_text(content, key, log.log_type))
        return log

    def dry_run(self, **fields):
        response = self.post('api_v1_rule_test', body={
            'status': B, 'match_type': 'substring', 'source_text': 'upd.exe', **fields,
        }, raw=self.helper_raw)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def test_forbidding_condition_leaves_out_logs_with_the_fact(self):
        self.stored('with-nvidia', WITH_NVIDIA)
        self.stored('without-nvidia', TARGET)
        body = self.dry_run(conditions=[{'fact': 'nvidia installed', 'polarity': 'forbid'}])
        self.assertEqual(body['logs_matched'], 1)
        [sample] = body['untrusted_sample']
        self.assertEqual([ref['upload_id'] for ref in sample['logs']], ['without-nvidia'])
        self.assertEqual(body['conditions_unchecked_logs'], 0)
        self.assertEqual(body['rule']['conditions'], 1)

    def test_logs_without_a_cached_analysis_are_unchecked(self):
        self.stored('never-analyzed', TARGET, analyze=False)
        body = self.dry_run(conditions=[{'fact_id': self.fact.pk, 'polarity': 'forbid'}])
        self.assertEqual(body['conditions_unchecked_logs'], 1)
        [sample] = body['untrusted_sample']
        self.assertEqual(sample['logs'][0]['conditions'], 'unchecked')

    def test_without_conditions_every_log_counts(self):
        self.stored('with-nvidia', WITH_NVIDIA)
        self.stored('without-nvidia', TARGET)
        body = self.dry_run()
        self.assertEqual(body['logs_matched'], 2)
        self.assertEqual(body['conditions_unchecked_logs'], 0)

    def test_entry_type_restriction(self):
        self.stored('a-log', TARGET, analyze=False)
        self.assertEqual(self.dry_run(only_entry_types=['runkey'])['logs_matched'], 1)
        self.assertEqual(self.dry_run(only_entry_types=['service'])['logs_matched'], 0)

    def test_compare_refuses_rules_with_conditions(self):
        saved = ClassificationRule.objects.create(owner=self.helper, status=B, match_type='substring', source_text='upd')
        response = self.post('api_v1_rule_test', body={
            'status': B, 'match_type': 'substring', 'source_text': 'upd.exe', 'compare_rule_id': saved.pk,
            'conditions': [{'fact_id': self.fact.pk}],
        }, raw=self.helper_raw)
        self.assertEqual(response.status_code, 400)
        self.assertIn('conditions', response.json()['error'])
