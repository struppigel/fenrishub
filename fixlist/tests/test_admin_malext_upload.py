from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from ..models import ClassificationRule
from .factories import make_rule, make_superuser, make_user


URL_NAME = 'admin:fixlist_classificationrule_import_malext_extensions'
CHANGELIST_URL_NAME = 'admin:fixlist_classificationrule_changelist'
SOURCE_LABEL = 'malext.io'


def _ext(prefix):
    """Build a valid 32-char a-p extension ID seeded from a short prefix."""
    base = (prefix * 32)[:32]
    return ''.join(c if c in 'abcdefghijklmnop' else 'a' for c in base)


def make_csv(rows, header=None, encoding='utf-8'):
    if header is None:
        header = 'extension_id,name,reason,source,date,blocklist,store'
    body = '\n'.join([header, *rows])
    return SimpleUploadedFile(
        'malext.csv',
        body.encode(encoding),
        content_type='text/csv',
    )


class AdminMalextImportTests(TestCase):
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
        self.assertContains(response, 'malext.io')

    # -- Happy path --

    def test_creates_rules_with_correct_fields(self):
        self.login_admin()
        ext_a = _ext('a')
        ext_b = _ext('b')
        csv = make_csv([
            f'{ext_a},Atlas,Bundling Unwanted Software,Store Monitoring,2026-07-26,,Chrome',
            f'{ext_b},Some Dropper,Malware,Store Monitoring,2026-07-26,true,Edge',
        ])
        response = self.client.post(self.url, {'csv_file': csv})
        self.assertRedirects(response, reverse(CHANGELIST_URL_NAME))

        self.assertEqual(ClassificationRule.objects.count(), 2)

        rule_a = ClassificationRule.objects.get(source_text=ext_a)
        self.assertEqual(rule_a.status, ClassificationRule.STATUS_PUP)
        self.assertEqual(rule_a.match_type, ClassificationRule.MATCH_SUBSTRING)
        self.assertEqual(rule_a.source_name, 'malext.io')
        self.assertEqual(rule_a.owner, self.admin)
        self.assertEqual(
            rule_a.description,
            f'from {SOURCE_LABEL}, Atlas, Bundling Unwanted Software',
        )

        rule_b = ClassificationRule.objects.get(source_text=ext_b)
        self.assertEqual(rule_b.status, ClassificationRule.STATUS_MALWARE)
        self.assertEqual(
            rule_b.description,
            f'from {SOURCE_LABEL}, Some Dropper, Malware',
        )

    def test_reason_malware_is_case_insensitive(self):
        self.login_admin()
        ext = _ext('a')
        self.client.post(
            self.url,
            {'csv_file': make_csv([f'{ext},Thing,MALWARE,,,,Chrome'])},
        )
        self.assertEqual(
            ClassificationRule.objects.get(source_text=ext).status,
            ClassificationRule.STATUS_MALWARE,
        )

    def test_non_malware_reasons_map_to_pup(self):
        self.login_admin()
        reasons = [
            'Adware',
            'Policy Violation',
            'Search Hijacking',
            'Removal reason Unknown',
            'Critical Vulnerability',
        ]
        rows = [
            f'{_ext(chr(ord("a") + i))},Ext {i},{reason},,,,Chrome'
            for i, reason in enumerate(reasons)
        ]
        self.client.post(self.url, {'csv_file': make_csv(rows)})
        self.assertEqual(len(reasons), ClassificationRule.objects.count())
        self.assertFalse(
            ClassificationRule.objects.exclude(
                status=ClassificationRule.STATUS_PUP
            ).exists()
        )

    def test_description_omits_missing_name(self):
        self.login_admin()
        ext_blank = _ext('a')
        ext_unknown = _ext('b')
        csv = make_csv([
            f'{ext_blank},,Adware,,,,Chrome',
            f'{ext_unknown},“UNKNOWN”,Adware,,,,Chrome',
        ])
        self.client.post(self.url, {'csv_file': csv})
        for ext in (ext_blank, ext_unknown):
            self.assertEqual(
                ClassificationRule.objects.get(source_text=ext).description,
                f'from {SOURCE_LABEL}, Adware',
            )

    def test_utf8_bom_header_is_handled(self):
        self.login_admin()
        ext = _ext('a')
        csv = make_csv(
            [f'{ext},Atlas,Adware,,,,Chrome'],
            encoding='utf-8-sig',
        )
        self.client.post(self.url, {'csv_file': csv})
        self.assertTrue(
            ClassificationRule.objects.filter(source_text=ext).exists()
        )

    # -- Duplicate rejection --

    def test_re_upload_skips_existing(self):
        self.login_admin()
        ext = _ext('a')
        rows = [f'{ext},First Name,Adware,,,,Chrome']
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
            {'csv_file': make_csv([f'{ext},Whatever,Adware,,,,Chrome'])},
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

    def test_id_embedded_in_another_rule_is_skipped(self):
        self.login_admin()
        ext_covered = _ext('a')
        ext_new = _ext('b')
        make_rule(
            r'C:\Users\jsnip\AppData\Local\Google\Chrome\User Data\Default'
            f'\\Extensions\\{ext_covered}',
            match_type=ClassificationRule.MATCH_FILEPATH,
        )
        self.client.post(
            self.url,
            {'csv_file': make_csv([
                f'{ext_covered},Covered,Adware,,,,Chrome',
                f'{ext_new},Fresh,Adware,,,,Chrome',
            ])},
        )
        self.assertFalse(
            ClassificationRule.objects.filter(
                source_text=ext_covered,
                match_type=ClassificationRule.MATCH_SUBSTRING,
            ).exists()
        )
        self.assertTrue(
            ClassificationRule.objects.filter(source_text=ext_new).exists()
        )

    def test_id_embedded_in_parsed_filepath_field_is_skipped(self):
        self.login_admin()
        ext = _ext('a')
        make_rule(
            'CHR Extension: (Bad One) - C:\\somewhere',
            match_type=ClassificationRule.MATCH_PARSED_ENTRY,
            filepath=(
                r'C:\Users\jsnip\AppData\Local\Google\Chrome\User Data\Default'
                f'\\Extensions\\{ext}'
            ),
        )
        self.client.post(
            self.url,
            {'csv_file': make_csv([f'{ext},Covered,Adware,,,,Chrome'])},
        )
        self.assertFalse(
            ClassificationRule.objects.filter(source_text=ext).exists()
        )

    def test_within_file_duplicate_creates_only_one(self):
        self.login_admin()
        ext = _ext('a')
        csv = make_csv([
            f'{ext},Name One,Adware,,,,Chrome',
            f'{ext},Name Two,Malware,,,,Chrome',
        ])
        self.client.post(self.url, {'csv_file': csv})
        self.assertEqual(
            ClassificationRule.objects.filter(source_text=ext).count(),
            1,
        )

    # -- Invalid rows --

    def test_skips_invalid_extids(self):
        self.login_admin()
        good = _ext('a')
        csv = make_csv([
            'short,Too Short,Adware,,,,Chrome',
            'ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP,Uppercase,Adware,,,,Chrome',
            'abcdefghijklmnopabcdefghijklmno1,Has Digit,Adware,,,,Chrome',
            'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq,Out Of Range,Adware,,,,Chrome',
            f'{good},Good One,Adware,,,,Chrome',
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
            {'csv_file': make_csv([f'{ext},Whatever,Adware,,,,Chrome'])},
        )
        rule = ClassificationRule.objects.get(source_text=ext)
        self.assertEqual(
            rule.priority,
            ClassificationRule.default_priority_for(
                ClassificationRule.MATCH_SUBSTRING
            ),
        )
