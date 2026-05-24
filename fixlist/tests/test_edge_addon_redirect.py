import urllib.error
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.urls import reverse

from .factories import make_user


class EdgeAddonRedirectTests(TestCase):

    def setUp(self):
        self.user = make_user()
        self.client.login(username=self.user.username, password='password123')
        self.valid_crxid = 'ihlecoggeaconmpkjmfjeplggdnemakk'

    def _url(self, crxid):
        return reverse('edge_addon_redirect', args=[crxid])

    def test_redirects_to_canonical_detail_page_when_api_returns_200(self):
        fake = MagicMock()
        fake.status = 200
        fake.__enter__.return_value = fake
        fake.__exit__.return_value = False
        with patch('fixlist.views.analyzer.urllib.request.urlopen', return_value=fake):
            response = self.client.get(self._url(self.valid_crxid))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response['Location'],
            f'https://microsoftedge.microsoft.com/addons/detail/_/{self.valid_crxid}',
        )

    def test_redirects_to_chrome_web_store_when_api_returns_404(self):
        err = urllib.error.HTTPError(
            url='', code=404, msg='Not Found', hdrs=None, fp=None,
        )
        with patch('fixlist.views.analyzer.urllib.request.urlopen', side_effect=err):
            response = self.client.get(self._url(self.valid_crxid))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response['Location'],
            f'https://chromewebstore.google.com/detail/{self.valid_crxid}',
        )

    def test_redirects_to_chrome_web_store_on_network_failure(self):
        err = urllib.error.URLError('connection refused')
        with patch('fixlist.views.analyzer.urllib.request.urlopen', side_effect=err):
            response = self.client.get(self._url(self.valid_crxid))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response['Location'],
            f'https://chromewebstore.google.com/detail/{self.valid_crxid}',
        )

    def test_redirects_to_chrome_web_store_on_timeout(self):
        with patch('fixlist.views.analyzer.urllib.request.urlopen', side_effect=TimeoutError()):
            response = self.client.get(self._url(self.valid_crxid))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response['Location'],
            f'https://chromewebstore.google.com/detail/{self.valid_crxid}',
        )

    def test_rejects_invalid_crxid_without_calling_upstream(self):
        with patch('fixlist.views.analyzer.urllib.request.urlopen') as mock_urlopen:
            response = self.client.get(self._url('not-a-real-crxid'))
        self.assertEqual(response.status_code, 400)
        mock_urlopen.assert_not_called()

    def test_rejects_uppercase_crxid(self):
        with patch('fixlist.views.analyzer.urllib.request.urlopen') as mock_urlopen:
            response = self.client.get(self._url(self.valid_crxid.upper()))
        self.assertEqual(response.status_code, 400)
        mock_urlopen.assert_not_called()

    def test_calls_upstream_with_expected_url_and_short_timeout(self):
        fake = MagicMock()
        fake.status = 200
        fake.__enter__.return_value = fake
        fake.__exit__.return_value = False
        with patch('fixlist.views.analyzer.urllib.request.urlopen', return_value=fake) as mock_urlopen:
            self.client.get(self._url(self.valid_crxid))

        call_args, call_kwargs = mock_urlopen.call_args
        request = call_args[0]
        self.assertEqual(
            request.full_url,
            f'https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{self.valid_crxid}',
        )
        # Timeout must be small so a Microsoft outage cannot stall a user click.
        self.assertLessEqual(call_kwargs.get('timeout', 999), 10)
