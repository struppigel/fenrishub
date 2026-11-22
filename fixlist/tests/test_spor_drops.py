"""Spor 0.8.0 lines: DROP FOLDERS (loader project folders linked by "group:"),
!lolbin-copy with a "shimcache:" sub-line, and cached Windows Installer
packages (!msi-script-action): parsing, correlations, parsed rules and the
summary box."""

from django.test import SimpleTestCase

from .. import log_highlighting, spor_extractors as se, spor_log
from ..correlations.spor_self import self_links
from . import spor8_sample as s

LINES = s.SPOR8.split('\n')


def no_of(text, start=0):
    """The number of the first line (after `start`) that contains `text`."""
    return next(no for no, line in enumerate(LINES, start=1) if no > start and text in line)


def linked(links, no):
    return {entry['line_no'] for entry in links.get(str(no), ())}


DROPS_AT = no_of('==================== DROP FOLDERS')


class SporDropsParsingTests(SimpleTestCase):
    def test_summary_lines_keep_the_grammar_and_their_tiers(self):
        items = {item.item: item for _no, item in spor_log.iter_summary_items(LINES)}
        for folder in (s.AMQP, s.PROTECT, s.THIRD):
            item = items[folder + '\\']
            self.assertEqual(item.tags, 'timeline DRP')
            self.assertEqual(item.status, '')
            self.assertEqual(item.flags, ['!known-malware', '!lolbin-copy'])
            self.assertEqual(spor_log.worst_tier(item.flags), 'malware')
        # Hidden is a detail ("attributes hidden"), never a status word: the path stays whole.
        self.assertIn('attributes hidden, folder', items[s.THIRD + '\\'].rest)
        msi = items[s.MSI]
        self.assertEqual((msi.status, msi.flags), ('unsigned', ['!msi-script-action']))
        self.assertEqual(spor_log.worst_tier(msi.flags), 'strong')
        copy = items[s.AMQP + '\\MSBuild.exe']
        self.assertEqual((copy.status, copy.flags), ('invalid signature', ['!lolbin', '!lolbin-copy']))

    def test_drop_folders_are_mentions_that_speak_for_their_files(self):
        mentions = [m for m in spor_log.iter_mentions(LINES) if m.section == spor_log.SECTION_DROPS]
        folders = {m.path: m for m in mentions if m.role == 'item'}
        self.assertEqual(set(folders), {s.AMQP, s.PROTECT, s.THIRD})
        self.assertTrue(all(m.folder for m in folders.values()))
        entries = {m.path: m for m in mentions if m.role == 'entry'}
        self.assertEqual(entries[s.AMQP + '\\MSBuild.exe'].status, 'invalid signature')
        self.assertIn(s.THIRD + '\\Resources.resx', entries)
        groups = [m for m in mentions if m.role == 'group']
        self.assertEqual([m.path for m in groups], [s.AMQP, s.AMQP])   # the first folder, without "\"
        self.assertEqual({m.parent_line for m in groups}, {no_of(s.PROTECT + '\\ =>', DROPS_AT), no_of(s.THIRD + '\\ =>', DROPS_AT)})

    def test_timeline_evidence_of_drop_folders_and_a_copy(self):
        evidence = {e.path: e for e in spor_log.iter_timeline_evidence(LINES)}
        self.assertEqual(evidence[s.THIRD + '\\'].sources, 'DRP')
        copy = evidence[s.AMQP + '\\MSBuild.exe']
        self.assertEqual(copy.sources, 'AM SRU')
        self.assertEqual(copy.time, '2026-11-20 09:15:00')   # not the copied file's July time
        self.assertEqual(copy.extra[0][0], 'shimcache')

    def test_a_cached_package_is_a_software_fact_with_its_product_code(self):
        cached = [f for f in spor_log.iter_software(LINES) if f.kind == 'cached']
        self.assertEqual(len(cached), 1)
        fact = cached[0]
        self.assertEqual(fact.name, 'Card Reader Helper')
        self.assertEqual(fact.details['product code'], '{' + s.CODE + '}')
        self.assertEqual(fact.details['publisher'], 'Realtek Semiconductor Corp.')
        self.assertEqual(fact.details['folder'].rstrip('\\'), s.LOCAL + '\\Realtek\\Card Reader Helper')
        self.assertEqual(fact.flags, ['!msi-script-action'])

    def test_a_cached_package_without_a_name_is_named_by_its_product_code(self):
        content = s.SPOR8.replace('=> name Card Reader Helper; version 2.6;', '=> version 2.6;')
        [fact] = [f for f in spor_log.iter_software(content.split('\n')) if f.kind == 'cached']
        self.assertEqual(fact.name, '{' + s.CODE + '}')


class SporDropsParsedRuleTests(SimpleTestCase):
    def test_a_cached_package_parses_without_its_random_file_name(self):
        no = no_of('[cached msi]')
        entry = se.parse_block([LINES[no - 1].strip(), LINES[no].strip(), LINES[no + 1].strip()])
        self.assertEqual(entry.entry_type, 'spor_cached_msi')
        self.assertEqual((entry.name, entry.company, entry.clsid), ('Card Reader Helper', 'Realtek Semiconductor Corp.', s.CODE))
        # the cached copy's file name and signature state differ between PCs: not part of the entry
        self.assertFalse(entry.file_not_signed)
        self.assertEqual(entry.filepath, '')

    def test_line_paths_for_file_path_rules(self):
        group = LINES[no_of('group:', DROPS_AT) - 1]
        self.assertEqual(se.line_path(group, sub_line=True), s.AMQP)
        self.assertFalse(se.is_entry_line(group, sub_line=True))   # it names another folder
        entry = LINES[no_of('entry: ' + s.THIRD + '\\MSBuild.exe') - 1]
        self.assertEqual(se.line_path(entry, sub_line=True), s.THIRD + '\\MSBuild.exe')
        folder = LINES[no_of(s.THIRD + '\\ =>', DROPS_AT) - 1]
        self.assertEqual(se.line_path(folder, sub_line=False), s.THIRD)
        self.assertEqual(se.line_path(LINES[no_of('[timeline DRP] ' + s.THIRD) - 1], sub_line=False), s.THIRD)


class SporDropsLinkTests(SimpleTestCase):
    def setUp(self):
        self.links = self_links('spor8', s.SPOR8)

    def test_every_group_line_links_to_the_first_folder(self):
        first = {no_of('[timeline DRP] ' + s.AMQP), no_of('[DRP] ' + s.AMQP), no_of(s.AMQP + '\\ =>', DROPS_AT)}
        groups = [no for no, line in enumerate(LINES, start=1) if line.strip().startswith('group:')]
        self.assertEqual(len(groups), 6)   # SUMMARY, TIMELINE, DROP FOLDERS: two members each
        for no in groups:
            with self.subTest(line=no):
                self.assertTrue(first <= linked(self.links, no))
        # and the first folder's line lists its members
        self.assertTrue(set(groups) <= linked(self.links, no_of(s.AMQP + '\\ =>', DROPS_AT)))

    def test_a_drop_folder_speaks_for_its_files_and_copies_link(self):
        folder = no_of(s.THIRD + '\\ =>', DROPS_AT)
        msbuild = no_of(s.THIRD + '\\MSBuild.exe => ')   # its FILES line
        self.assertIn(msbuild, linked(self.links, folder))
        copies = linked(self.links, no_of(s.AMQP + '\\MSBuild.exe => '))
        self.assertIn(msbuild, copies)   # same SHA256

    def test_a_cached_package_links_to_its_install_event_by_product_code(self):
        cached = no_of('[cached msi]')
        matches = {entry['line_no']: entry.get('match') for entry in self.links.get(str(cached), ())}
        self.assertEqual(matches.get(no_of('[1033] installed: Card Reader Helper')), 'msi')
        self.assertIn(no_of(s.MSI + ' => '), matches)   # its FILES line

    def test_every_install_folder_of_a_cached_package_speaks_for_its_files(self):
        second = s.LOCAL + '\\Realtek\\Updater'
        content = s.SPOR8.replace(
            f'    folder: {s.LOCAL}\\Realtek\\Card Reader Helper\\\n',
            f'    folder: {s.LOCAL}\\Realtek\\Card Reader Helper\\\n    folder: {second}\\\n',
        ).replace(
            f'{s.MSI} => {s.MSI_SHA}, signature unsigned\n',
            f'{s.MSI} => {s.MSI_SHA}, signature unsigned\n{second}\\upd.exe => {"ee" * 32}, signature unsigned\n',
        )
        lines = content.split('\n')
        upd = next(no for no, line in enumerate(lines, start=1) if line.startswith(second + '\\upd.exe => '))
        cached = next(no for no, line in enumerate(lines, start=1) if '[cached msi]' in line)
        self.assertIn(cached, linked(self_links('spor8', content), upd))

    def test_a_tab_indented_group_line_links_too(self):
        content = s.SPOR8.replace(f'\n    group: {s.AMQP}\\', f'\n\tgroup: {s.AMQP}\\', 1)   # the SUMMARY one
        lines = content.split('\n')
        group = next(no for no, line in enumerate(lines, start=1) if line.startswith('\tgroup:'))
        first = next(no for no, line in enumerate(lines, start=1) if line.startswith('2026-11-20 09:11:12 [timeline DRP] ' + s.AMQP))
        self.assertIn(first, linked(self_links('spor8', content), group))


class SporDropsHighlightTests(SimpleTestCase):
    def test_summary_box_rates_drop_folders_as_malware(self):
        result = log_highlighting.highlight_log('Spor', s.SPOR8)
        severities = {item.name: item.severity for item in result.summary}
        for folder in (s.AMQP, s.PROTECT, s.THIRD):
            self.assertEqual(severities[folder + '\\'], 'b')
        self.assertEqual(severities[s.MSI], 'w')
        self.assertEqual(len(result.summary), 5)
