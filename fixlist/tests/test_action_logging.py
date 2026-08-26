"""Tests for ActionLogMiddleware.

The middleware exists because a Gunicorn worker timeout (SIGABRT -> SystemExit)
kills the request without running any post-response code, leaving a traceback
with no indication of which button was pressed or which upload was involved.
The breadcrumb must therefore be emitted BEFORE the view runs, and must never
echo request bodies (pasted log content, fixlist text, credentials).
"""
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase

from ..middleware import ActionLogMiddleware, MAX_LOGGED_IDS


class ActionLogMiddlewareTests(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def _run(self, request, view=None, logger_name='fixlist.middleware'):
        middleware = ActionLogMiddleware(view or (lambda req: _Response(200)))
        with self.assertLogs(logger_name, level='INFO') as captured:
            response = middleware(request)
        return response, captured.output

    def _post(self, path='/uploaded-logs/', data=None, user=None):
        # Button-driven actions in this app submit urlencoded forms; the
        # middleware deliberately ignores multipart (see the stream tests below),
        # and RequestFactory would otherwise default to multipart.
        request = self.factory.post(
            path,
            urlencode(data or {}, doseq=True),
            content_type='application/x-www-form-urlencoded',
        )
        request.user = user or _AnonymousUser()
        return request

    def test_get_requests_are_not_logged(self):
        request = self.factory.get('/uploaded-logs/')
        request.user = _AnonymousUser()
        middleware = ActionLogMiddleware(lambda req: _Response(200))
        # assertNoLogs would fail the test if the middleware logged anything.
        with self.assertNoLogs('fixlist.middleware', level='INFO'):
            response = middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_post_logs_action_and_selected_uploads(self):
        user = User.objects.create_user(username='analyst', password='pw')
        request = self._post(
            data={'action': 'merge', 'selected_upload_ids': ['alpha-beta', 'gamma-delta']},
            user=user,
        )
        _response, output = self._run(request)

        start_lines = [line for line in output if 'action start' in line]
        self.assertEqual(len(start_lines), 1)
        line = start_lines[0]
        self.assertIn('path=/uploaded-logs/', line)
        self.assertIn('user=analyst', line)
        self.assertIn('action=merge', line)
        self.assertIn('selected_upload_ids=[alpha-beta,gamma-delta]', line)

    def test_breadcrumb_is_emitted_before_the_view_runs(self):
        """The whole point: a killed request must still leave the breadcrumb."""
        seen = []

        def view(request):
            seen.append('view ran')
            return _Response(200)

        request = self._post(data={'action': 'merge'})
        middleware = ActionLogMiddleware(view)
        with self.assertLogs('fixlist.middleware', level='INFO') as captured:
            middleware(request)

        # The log record was created while the view had not yet been entered,
        # which is what survives a SIGABRT mid-view.
        self.assertIn('action start', captured.output[0])
        self.assertEqual(seen, ['view ran'])

    def test_anonymous_user_is_labelled(self):
        request = self._post(data={'action': 'upload'})
        _response, output = self._run(request)
        self.assertIn('user=anon', output[0])

    def test_request_body_is_never_logged(self):
        request = self._post(
            data={
                'action': 'upload',
                'content': 'HKLM\\SOFTWARE\\Secret => C:\\Users\\victim\\evil.exe',
                'password': 'hunter2',
                'log_text': 'sensitive pasted log',
            },
        )
        _response, output = self._run(request)
        joined = '\n'.join(output)
        self.assertIn('action=upload', joined)
        self.assertNotIn('hunter2', joined)
        self.assertNotIn('victim', joined)
        self.assertNotIn('sensitive pasted log', joined)

    def test_long_id_lists_are_truncated(self):
        ids = [f'log-{index}' for index in range(MAX_LOGGED_IDS + 5)]
        request = self._post(data={'action': 'merge', 'selected_upload_ids': ids})
        _response, output = self._run(request)
        line = output[0]
        self.assertIn('(+5 more)', line)
        self.assertNotIn(f'log-{MAX_LOGGED_IDS + 4}', line)

    def test_multipart_post_does_not_consume_the_upload_stream(self):
        """Reading request.POST here would make a later request.body raise
        RawPostDataException, which the JSON API views rely on."""
        upload = SimpleUploadedFile('FRST.txt', b'scan contents', content_type='text/plain')
        request = self.factory.post('/upload/', {'action': 'upload', 'logfile': upload})
        request.user = _AnonymousUser()

        read_body = {}

        def view(req):
            read_body['value'] = req.body
            return _Response(200)

        middleware = ActionLogMiddleware(view)
        with self.assertLogs('fixlist.middleware', level='INFO') as captured:
            middleware(request)

        self.assertIn(b'scan contents', read_body['value'])
        self.assertIn('content_type=multipart/form-data', captured.output[0])

    def test_json_post_body_stays_readable(self):
        request = self.factory.post(
            '/api/rules/', data='{"name": "x"}', content_type='application/json'
        )
        request.user = _AnonymousUser()

        read_body = {}

        def view(req):
            read_body['value'] = req.body
            return _Response(200)

        middleware = ActionLogMiddleware(view)
        with self.assertLogs('fixlist.middleware', level='INFO'):
            middleware(request)

        self.assertEqual(read_body['value'], b'{"name": "x"}')

    def test_slow_requests_still_warn_when_info_breadcrumbs_are_off(self):
        """Production may quieten the breadcrumbs to WARNING; the slow-request
        signal is the one that predicts a worker timeout, so it must survive."""
        request = self._post(data={'action': 'merge'})
        middleware = ActionLogMiddleware(lambda req: _Response(200))

        import fixlist.middleware as middleware_module

        original = middleware_module.SLOW_REQUEST_SECONDS
        middleware_module.SLOW_REQUEST_SECONDS = 0.0
        try:
            with self.assertLogs('fixlist.middleware', level='WARNING') as captured:
                middleware(request)
        finally:
            middleware_module.SLOW_REQUEST_SECONDS = original

        self.assertTrue(any('action slow' in line for line in captured.output))
        self.assertFalse(any('action start' in line for line in captured.output))

    def test_error_response_is_logged_with_status(self):
        request = self._post(data={'action': 'merge'})
        _response, output = self._run(request, view=lambda req: _Response(500))
        self.assertTrue(any('action failed' in line and '500' in line for line in output))

    def test_view_exception_is_logged_and_reraised(self):
        def view(request):
            raise ValueError('boom')

        request = self._post(data={'action': 'merge'})
        middleware = ActionLogMiddleware(view)
        with self.assertLogs('fixlist.middleware', level='INFO') as captured:
            with self.assertRaises(ValueError):
                middleware(request)
        self.assertTrue(any('action raised' in line for line in captured.output))


class _Response:
    def __init__(self, status_code):
        self.status_code = status_code


class _AnonymousUser:
    is_authenticated = False
    username = ''
