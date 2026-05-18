from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from ..models import ClassificationRule
from .factories import make_rule, make_superuser, make_user


URL_NAME = 'admin:fixlist_classificationrule_import_chrome_extensions'
CHANGELIST_URL_NAME = 'admin:fixlist_classificationrule_changelist'
SOURCE_URL = 'https://github.com/mallorybowes/chrome-mal-ids'


def _ext(prefix):
    """Build a valid 32-char a-p EXTID seeded from a short prefix."""
    base = (prefix * 32)[:32]
    return ''.join(c if c in 'abcdefghijklmnop' else 'a' for c in base)


def make_csv(rows, header=None):
    if header is None:
        header = 'EXTID,EXTID-NAME,STILL-ACTIVE'
    body = '\n'.join([header, *rows])
    return SimpleUploadedFile(
        'chrome.csv',
        body.encode('utf-8'),
        content_type='text/csv',
    )


class AdminChromeExtensionImportTests(TestCase):
    def setUp(self):
        self.admin = make_superuser()
        self.url = reverse(URL_NAME)

    def login_admin(self):
        self.client.login(username='admin', password='password123')

    # -- Auth --

    def test_anonymous_redirected_to_admin_login(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login', response.url)

    def test_non_staff_redirected_to_admin_login(self):
        make_user(username='carol', password='password123')
        self.client.login(username='carol', password='password123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login', response.url)

    def test_admin_get_renders(self):
        self.login_admin()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Chrome extension')

    # -- Happy path --

    def test_creates_rules_with_correct_fields(self):
        self.login_admin()
        ext_a = _ext('a')
        ext_b = _ext('b')
        ext_c = _ext('c')
        csv = make_csv([
            f'{ext_a},Coolest Extension,1',
            f'{ext_b},“UNKNOWN”,unknown',
            f'{ext_c},“See SOURCE/NOTES Fields”,unknown',
        ])
        response = self.client.post(self.url, {'csv_file': csv})
        self.assertRedirects(response, reverse(CHANGELIST_URL_NAME))

        self.assertEqual(ClassificationRule.objects.count(), 3)

        rule_a = ClassificationRule.objects.get(source_text=ext_a)
        self.assertEqual(rule_a.status, ClassificationRule.STATUS_MALWARE)
        self.assertEqual(rule_a.match_type, ClassificationRule.MATCH_SUBSTRING)
        self.assertEqual(rule_a.source_name, 'chrome-mal-ids')
        self.assertEqual(rule_a.owner, self.admin)
        self.assertEqual(rule_a.description, f'Coolest Extension - {SOURCE_URL}')

        rule_b = ClassificationRule.objects.get(source_text=ext_b)
        self.assertEqual(rule_b.description, SOURCE_URL)

        rule_c = ClassificationRule.objects.get(source_text=ext_c)
        self.assertEqual(rule_c.description, SOURCE_URL)

    # -- Duplicate rejection --

    def test_re_upload_skips_existing(self):
        self.login_admin()
        ext = _ext('a')
        rows = [f'{ext},First Name,1']
        self.client.post(self.url, {'csv_file': make_csv(rows)})
        self.client.post(self.url, {'csv_file': make_csv(rows)})
        self.assertEqual(
            ClassificationRule.objects.filter(source_text=ext).count(),
            1,
        )

    def test_duplicate_check_is_global_across_owners(self):
        self.login_admin()
        ext = _ext('a')
        other = make_user(username='other', password='password123')
        make_rule(
            ext,
            owner=other,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_SUBSTRING,
        )
        self.client.post(
            self.url,
            {'csv_file': make_csv([f'{ext},Whatever,1'])},
        )
        # Still just the one rule owned by 'other'; admin did not create a copy.
        self.assertEqual(
            ClassificationRule.objects.filter(source_text=ext).count(),
            1,
        )
        self.assertEqual(
            ClassificationRule.objects.get(source_text=ext).owner,
            other,
        )

    def test_within_file_duplicate_creates_only_one(self):
        self.login_admin()
        ext = _ext('a')
        csv = make_csv([
            f'{ext},Name One,1',
            f'{ext},Name Two,1',
        ])
        self.client.post(self.url, {'csv_file': csv})
        self.assertEqual(
            ClassificationRule.objects.filter(source_text=ext).count(),
            1,
        )

    # -- Inactive filter --

    def test_skips_still_active_zero(self):
        self.login_admin()
        ext_active = _ext('a')
        ext_inactive = _ext('b')
        csv = make_csv([
            f'{ext_active},Active One,1',
            f'{ext_inactive},Inactive One,0',
        ])
        self.client.post(self.url, {'csv_file': csv})
        self.assertTrue(
            ClassificationRule.objects.filter(source_text=ext_active).exists()
        )
        self.assertFalse(
            ClassificationRule.objects.filter(source_text=ext_inactive).exists()
        )

    def test_keeps_still_active_unknown(self):
        self.login_admin()
        ext = _ext('a')
        csv = make_csv([f'{ext},Some Name,unknown'])
        self.client.post(self.url, {'csv_file': csv})
        self.assertTrue(
            ClassificationRule.objects.filter(source_text=ext).exists()
        )

    # -- Invalid rows --

    def test_skips_invalid_extids(self):
        self.login_admin()
        good = _ext('a')
        csv = make_csv([
            'short,Too Short,1',
            'ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP,Uppercase,1',
            'abcdefghijklmnopabcdefghijklmno1,Has Digit,1',
            f'{good},Good One,1',
        ])
        self.client.post(self.url, {'csv_file': csv})
        self.assertEqual(ClassificationRule.objects.count(), 1)
        self.assertEqual(
            ClassificationRule.objects.first().source_text,
            good,
        )

    # -- Priority default --

    def test_priority_defaults_to_substring_default(self):
        self.login_admin()
        ext = _ext('a')
        self.client.post(
            self.url,
            {'csv_file': make_csv([f'{ext},Whatever,1'])},
        )
        rule = ClassificationRule.objects.get(source_text=ext)
        self.assertEqual(
            rule.priority,
            ClassificationRule.default_priority_for(
                ClassificationRule.MATCH_SUBSTRING
            ),
        )
