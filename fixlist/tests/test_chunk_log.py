"""Tests for the `chunk_log` template filter used in templates/view_uploaded_log.html.

The uploaded-log viewer renders content as chunked blocks so the browser can
skip off-screen layout (content-visibility: auto). The copy/download buttons
rebuild the full log by joining the rendered chunk text with '\\n', so the
critical invariant is that '\\n'.join(chunk_log(content)) == content.
"""

from django.test import TestCase

from ..templatetags.rule_tags import chunk_log


class ChunkLogTests(TestCase):
    def _assert_roundtrip(self, content, n=100):
        chunks = chunk_log(content, n)
        self.assertEqual('\n'.join(chunks), content)
        return chunks

    def test_empty_content_yields_no_chunks(self):
        self.assertEqual(chunk_log(''), [])
        self.assertEqual(chunk_log(None), [])

    def test_chunks_split_by_line_count(self):
        content = '\n'.join(f'line{i}' for i in range(250))
        chunks = self._assert_roundtrip(content, 100)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0].count('\n'), 99)  # 100 lines
        self.assertEqual(chunks[2], 'line200\nline201\n' + '\n'.join(
            f'line{i}' for i in range(202, 250)))

    def test_roundtrip_preserves_blank_lines_and_trailing_newline(self):
        # FRST logs contain blank separator lines and may end with a newline.
        content = 'first\n\n\nmiddle\nlast\n'
        self._assert_roundtrip(content, 2)

    def test_roundtrip_with_crlf_left_intact(self):
        # HTML parsing normalises CR away in the DOM, but the filter itself must
        # not mangle stored content; split/join on '\n' is lossless here.
        content = 'a\r\nb\r\nc'
        self._assert_roundtrip(content, 2)

    def test_fewer_lines_than_chunk_size_is_single_chunk(self):
        content = 'only\ntwo'
        chunks = self._assert_roundtrip(content, 100)
        self.assertEqual(chunks, ['only\ntwo'])

    def test_invalid_chunk_size_falls_back_to_default(self):
        content = '\n'.join(f'line{i}' for i in range(150))
        self.assertEqual(len(chunk_log(content, 0)), 2)
        self.assertEqual(len(chunk_log(content, 'bogus')), 2)
