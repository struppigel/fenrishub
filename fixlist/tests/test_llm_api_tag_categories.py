"""Tag categories through the token API: listing them, and creating or moving a
tag by category id or name. Additive: a request without the new fields keeps
its old meaning, so older MCP clients keep working."""

from ..models import RuleTag, TagCategory
from ..views.api_auth import API_VERSION_HEADER
from .test_llm_api_write import ApiWriteBase


class TagCategoryListTests(ApiWriteBase):
    def setUp(self):
        super().setUp()
        self.default = TagCategory.get_default()
        self.families = TagCategory.objects.create(name='Families', color='#aa0000', priority=7)
        RuleTag.objects.create(name='Emotet', category=self.families, match_statuses=['B'])

    def test_any_token_lists_the_categories(self):
        response = self.get('api_v1_tag_categories')
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(int(response[API_VERSION_HEADER]), 5)
        rows = {row['name']: row for row in response.json()['categories']}
        self.assertEqual(rows['Families'], {
            'category_id': self.families.pk, 'name': 'Families', 'color': '#aa0000',
            'priority': 7, 'is_default': False, 'tag_count': 1,
        })
        self.assertTrue(rows[self.default.name]['is_default'])


class TagCategoryWriteTests(ApiWriteBase):
    def setUp(self):
        super().setUp()
        self.default = TagCategory.get_default()
        self.families = TagCategory.objects.create(name='Families', color='#aa0000')
        self.vendors = TagCategory.objects.create(name='Vendors', color='#00aa00')

    def create(self, **fields):
        return self.post('api_v1_tag_create', body={'name': 'Emotet', 'match_statuses': ['B'], **fields})

    def test_create_without_a_category_gets_the_default_as_before(self):
        response = self.create()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(RuleTag.objects.get(name='Emotet').category, self.default)

    def test_create_by_category_id_as_before(self):
        response = self.create(category_id=self.families.pk)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()['category_id'], self.families.pk)

    def test_create_by_category_name_ignores_case(self):
        response = self.create(category='  families ')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(RuleTag.objects.get(name='Emotet').category, self.families)
        self.assertEqual(response.json()['category']['name'], 'Families')

    def test_unknown_category_name_creates_nothing(self):
        response = self.create(category='Nope')
        self.assertEqual(response.status_code, 400)
        self.assertIn('Unknown tag category', response.json()['error'])
        self.assertFalse(RuleTag.objects.filter(name='Emotet').exists())

    def test_name_and_id_must_agree(self):
        response = self.create(category='Families', category_id=self.vendors.pk)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(RuleTag.objects.filter(name='Emotet').exists())
        agreeing = self.create(category='Families', category_id=self.families.pk)
        self.assertEqual(agreeing.status_code, 201)

    def test_category_name_must_be_a_string(self):
        self.assertEqual(self.create(category=3).status_code, 400)
        self.assertEqual(self.create(category='').status_code, 400)

    def test_update_moves_the_tag_by_name_and_keeps_other_fields(self):
        tag = RuleTag.objects.create(name='Emotet', description='banking', match_statuses=['B'],
                                     category=self.families)
        response = self.post('api_v1_tag_update', tag.pk, body={'category': 'vendors'})
        self.assertEqual(response.status_code, 200)
        tag.refresh_from_db()
        self.assertEqual(tag.category, self.vendors)
        self.assertEqual(tag.description, 'banking')

    def test_update_by_category_id_as_before(self):
        tag = RuleTag.objects.create(name='Emotet', match_statuses=['B'], category=self.families)
        self.post('api_v1_tag_update', tag.pk, body={'category_id': self.vendors.pk})
        tag.refresh_from_db()
        self.assertEqual(tag.category, self.vendors)

    def test_update_without_a_category_keeps_it(self):
        tag = RuleTag.objects.create(name='Emotet', match_statuses=['B'], category=self.families)
        self.post('api_v1_tag_update', tag.pk, body={'description': 'changed'})
        tag.refresh_from_db()
        self.assertEqual(tag.category, self.families)

    def test_update_with_an_unknown_name_changes_nothing(self):
        tag = RuleTag.objects.create(name='Emotet', description='banking', match_statuses=['B'],
                                     category=self.families)
        response = self.post('api_v1_tag_update', tag.pk, body={'category': 'Nope', 'description': 'x'})
        self.assertEqual(response.status_code, 400)
        tag.refresh_from_db()
        self.assertEqual((tag.category, tag.description), (self.families, 'banking'))

    def test_writing_still_needs_a_write_token(self):
        response = self.post(
            'api_v1_tag_create', body={'name': 'x', 'match_statuses': ['B'], 'category': 'Families'},
            raw=self.admin_read_raw,
        )
        self.assertEqual(response.status_code, 403)

    def test_null_category_means_the_default_like_category_id(self):
        response = self.create(category=None)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(RuleTag.objects.get(name='Emotet').category, self.default)
