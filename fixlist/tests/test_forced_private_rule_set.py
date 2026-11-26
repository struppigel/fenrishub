"""A helper a superuser forced into their private rule set (training mode)
sees no other helper's rules and no verdicts of another rule set."""
import json

from django.core.cache import cache
from django.template.loader import render_to_string
from django.test import RequestFactory, TestCase
from django.urls import reverse

from ..analyzer import invalidate_rule_buckets_cache
from ..models import (
    ApiToken,
    ClassificationRule,
    Fact,
    FactRule,
    RuleTag,
    SiteConfig,
    UploadedLogAnalysis,
    UserProfile,
)
from ..rule_sets import (
    counts_visible_to,
    is_restricted_key,
    is_rule_restricted,
    set_forced_private,
)
from ..tagging import found_tags_by_upload
from .factories import make_rule, make_superuser, make_uploaded_log, make_user

SHARED_LINE = 'TEAM-ONLY-MALWARE-LINE'


class ForcedPrivateTestBase(TestCase):
    def setUp(self):
        cache.clear()
        self.mentor = make_user('mentor')
        UserProfile.objects.create(user=self.mentor, rule_set_mode='shared')
        self.shared_rule = make_rule(SHARED_LINE, owner=self.mentor, description='team secret description')
        self.trainee = make_user('trainee')
        self.profile = UserProfile.objects.create(user=self.trainee)
        set_forced_private(self.profile, True)
        invalidate_rule_buckets_cache()
        self.client.login(username='trainee', password='password123')

    def post_json(self, name, payload):
        return self.client.post(reverse(name), data=json.dumps(payload), content_type='application/json')


class ForcingTests(ForcedPrivateTestBase):
    def test_forcing_makes_the_mode_private_and_restricts(self):
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.rule_set_mode, 'private')
        self.assertTrue(is_rule_restricted(self.trainee))
        self.assertTrue(is_restricted_key(f'private:{self.trainee.id}'))
        self.assertFalse(is_restricted_key(f'private:{self.mentor.id}'))
        self.assertFalse(is_restricted_key('shared'))

    def test_saving_a_forced_profile_keeps_it_private(self):
        self.profile.rule_set_mode = 'shared'
        self.profile.save(update_fields=['rule_set_mode'])
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.rule_set_mode, 'private')

    def test_profile_page_cannot_switch_back_to_shared(self):
        response = self.client.post(reverse('profile'), {'rule_set_mode': 'shared'})
        self.assertEqual(response.status_code, 302)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.rule_set_mode, 'private')
        page = self.client.get(reverse('profile'))
        self.assertContains(page, 'Set by an administrator')

    def test_released_helper_can_switch_again(self):
        set_forced_private(self.profile, False)
        self.assertFalse(is_rule_restricted(self.trainee))
        self.client.post(reverse('profile'), {'rule_set_mode': 'shared'})
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.rule_set_mode, 'shared')

    def test_superuser_is_never_restricted(self):
        admin = make_superuser()
        UserProfile.objects.create(user=admin, force_private_rule_set=True)
        self.assertFalse(is_rule_restricted(admin))


class AdminTests(ForcedPrivateTestBase):
    def test_staff_who_is_not_superuser_cannot_open_profiles_admin(self):
        make_user('staffer', is_staff=True)
        self.client.login(username='staffer', password='password123')
        response = self.client.get(reverse('admin:fixlist_userprofile_changelist'))
        self.assertEqual(response.status_code, 403)

    def test_superuser_forces_a_helper_from_the_admin(self):
        helper = make_user('helper')
        profile = UserProfile.objects.create(user=helper, rule_set_mode='shared')
        make_superuser()
        self.client.login(username='admin', password='password123')
        response = self.client.post(reverse('admin:fixlist_userprofile_changelist'), {
            'action': 'force_private_rule_set_action',
            '_selected_action': [profile.pk],
        })
        self.assertEqual(response.status_code, 302)
        profile.refresh_from_db()
        self.assertTrue(profile.force_private_rule_set)
        self.assertEqual(profile.rule_set_mode, 'private')


class RuleContentHiddenTests(ForcedPrivateTestBase):
    def test_rules_page_all_tab_shows_only_own_rules(self):
        own = make_rule('TRAINEE-OWN-LINE', owner=self.trainee)
        response = self.client.get(reverse('rules'), {'filter': 'all'})
        rule_ids = {item.pk for item in response.context['page_obj'] if isinstance(item, ClassificationRule)}
        self.assertEqual(rule_ids, {own.pk})
        self.assertNotContains(response, 'filter=others')

    def test_rules_page_id_and_line_search_skip_other_rules(self):
        by_id = self.client.get(reverse('rules'), {'q': str(self.shared_rule.pk), 'search_mode': 'id'})
        self.assertEqual(list(by_id.context['page_obj']), [])
        by_line = self.client.get(reverse('rules'), {'q': SHARED_LINE, 'search_mode': 'line', 'filter': 'all'})
        self.assertEqual(list(by_line.context['page_obj']), [])

    def test_line_inspector_uses_own_rule_set(self):
        response = self.post_json('analyze_line_details_api', {'line': SHARED_LINE})
        inspection = response.json()['inspection']
        self.assertEqual(inspection['matches'], [])
        self.assertNotContains(response, 'team secret description')

    def test_conflict_preview_lists_no_shared_rules(self):
        response = self.post_json('preview_pending_rule_changes_api', {'pending_changes': [{
            'id': '1', 'line': SHARED_LINE, 'original_status': '?',
            'new_status': ClassificationRule.STATUS_CLEAN, 'order': 1,
        }]})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'team secret description')
        self.assertEqual(response.json()['summary']['override_conflicts'], 0)

    def test_tag_preview_scans_only_own_rules(self):
        response = self.post_json('rule_tag_preview_api', {'pattern': 'team secret'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['counts']['new'], 0)

    def test_fact_editor_hides_other_fact_rules(self):
        fact = Fact.objects.create(name='team_fact')
        FactRule.objects.create(
            fact=fact, owner=self.mentor, match_type=FactRule.MATCH_SUBSTRING, source_text='MENTOR-FACT-TEXT',
        )
        response = self.client.get(reverse('fact_edit', args=[fact.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['fact_rules'], [])

    def test_no_api_token_can_be_created_or_used(self):
        response = self.client.post(reverse('api_tokens'), {'action': 'create', 'name': 'laptop'})
        self.assertContains(response, 'API tokens are off')
        self.assertFalse(ApiToken.objects.filter(user=self.trainee).exists())

        config = SiteConfig.get_solo()
        config.api_enabled = True
        config.save()
        set_forced_private(self.profile, False)
        _token, raw = ApiToken.issue(self.trainee, 'laptop')
        set_forced_private(self.profile, True)
        response = self.client.get(reverse('api_v1_rules'), secure=True, HTTP_AUTHORIZATION=f'Bearer {raw}')
        self.assertEqual(response.status_code, 403)


class VerdictsHiddenTests(ForcedPrivateTestBase):
    def setUp(self):
        super().setUp()
        # Unassigned: analysed and counted with the shared rules.
        self.log = make_uploaded_log('team-log', content=SHARED_LINE, log_type='FRST')
        self.log.recalculate_analysis_stats()
        self.log.refresh_from_db()
        self.assertEqual(self.log.count_malware, 1)

    def _chips(self, user):
        request = RequestFactory().get('/')
        request.user = user
        return render_to_string('partials/upload_stat_chips.html', {'uploaded_log': self.log, 'request': request})

    def test_status_chips_of_unassigned_log_are_hidden(self):
        self.assertFalse(counts_visible_to(self.log, self.trainee))
        self.assertNotIn('B 1', self._chips(self.trainee))
        self.assertIn('B 1', self._chips(self.mentor))

    def test_chips_of_own_assigned_log_are_shown(self):
        self.log.recipient_user = self.trainee
        self.log.save(update_fields=['recipient_user'])
        self.assertTrue(counts_visible_to(self.log, self.trainee))

    def test_tag_search_never_falls_back_to_shared_analysis(self):
        tag = RuleTag.objects.create(name='TeamTag')
        self.shared_rule.tags.add(tag)
        self.assertTrue(UploadedLogAnalysis.objects.filter(upload=self.log, rule_set_key='shared').exists())
        mentor_private = make_user('loner')
        UserProfile.objects.create(user=mentor_private, rule_set_mode='private')
        # A plain private helper still gets the shared fallback...
        found = found_tags_by_upload([self.log.pk], f'private:{mentor_private.id}')
        self.assertEqual([t['name'] for t in found[self.log.pk]], ['TeamTag'])
        # ...a forced one does not.
        found = found_tags_by_upload([self.log.pk], f'private:{self.trainee.id}')
        self.assertEqual(found[self.log.pk], [])


class PlainPrivateInspectorTests(TestCase):
    """The inspector bug fix for every private helper, forced or not."""

    def test_private_helper_inspector_uses_own_rules(self):
        mentor = make_user('mentor')
        UserProfile.objects.create(user=mentor, rule_set_mode='shared')
        make_rule(SHARED_LINE, owner=mentor)
        helper = make_user('helper')
        UserProfile.objects.create(user=helper, rule_set_mode='private')
        own = make_rule(SHARED_LINE, owner=helper, status=ClassificationRule.STATUS_CLEAN)
        self.client.login(username='helper', password='password123')
        response = self.client.post(
            reverse('analyze_line_details_api'), data=json.dumps({'line': SHARED_LINE}),
            content_type='application/json',
        )
        matches = response.json()['inspection']['matches']
        self.assertEqual([m['id'] for m in matches], [own.pk])
