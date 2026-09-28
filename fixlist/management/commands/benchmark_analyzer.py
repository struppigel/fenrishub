"""Time the log analyzer against real uploaded logs.

Splits one `analyze_log_text` run into the parts that can regress separately:
loading the rules, matching every line against them, and everything else done
per line (verdict, colouring, result building), plus the JSON the result
serialises to. Only uses analyzer entry points that have been stable for a long
time, so the same command can be dropped into an older checkout (e.g. a git
worktree of a previous commit) to produce a comparable baseline.
"""

import cProfile
import hashlib
import io
import json
import pstats
import statistics
import time

from django.core.management.base import BaseCommand
from django.db.models.functions import Length

from fixlist import analyzer
from fixlist.models import UploadedLog
from fixlist.rule_sets import SHARED_RULE_SET_KEY


class Command(BaseCommand):
    help = (
        'Benchmark analyze_log_text on the largest uploaded logs (or given ones): rule '
        'loading, per-line matching, the remaining per-line work, and the JSON payload. '
        'Use --save/--compare to check that two code versions give the same verdicts.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--largest', type=int, default=5,
                            help='Benchmark the N largest distinct uploaded logs (default: 5).')
        parser.add_argument('--upload-id', action='append', default=[],
                            help='Benchmark this upload instead (repeatable).')
        parser.add_argument('--runs', type=int, default=5,
                            help='Timed repeats of the per-line work and json.dumps after one '
                                 'warm-up (default: 5). Matching and the full analysis, which '
                                 'take far longer, are timed once per log.')
        parser.add_argument('--rule-set', default=SHARED_RULE_SET_KEY,
                            help='Rule set key to analyse with (default: shared).')
        parser.add_argument('--profile', action='store_true',
                            help='cProfile one analyze_log_text run on the first log.')
        parser.add_argument('--save', help='Write per-line verdict and colouring to this JSON file.')
        parser.add_argument('--compare', help='Compare per-line results against a --save file.')
        parser.add_argument('--dump-payload',
                            help='Write the first log\'s payload as a JS file for bench_render.html.')

    def handle(self, *args, **opts):
        logs = self._select_logs(opts)
        if not logs:
            self.stderr.write('No uploaded logs to benchmark.')
            return

        rule_set = opts['rule_set']
        start = time.perf_counter()
        buckets = analyzer._load_rule_buckets(rule_set)
        load_seconds = time.perf_counter() - start

        # Pin the rules for the whole run: the regular cache expires after a
        # minute, which a large log can outlast, and a reload mid-run would be
        # timed as analyzer work.
        original_get_buckets = analyzer._get_cached_rule_buckets
        analyzer._get_cached_rule_buckets = lambda *_args, **_kwargs: buckets

        self.stdout.write(self.style.MIGRATE_HEADING('Rules'))
        self.stdout.write(f'  bucket load (cold)   : {load_seconds * 1000:9.1f} ms')
        for key, value in buckets.items():
            if isinstance(value, (list, dict, set)):
                self.stdout.write(f'  {key:<28}: {len(value)}')

        saved = {}
        try:
            for log in logs:
                saved[log.upload_id] = self._benchmark_log(log, buckets, rule_set, opts['runs'])
            if opts['profile']:
                self._profile(logs[0], rule_set)
            if opts['dump_payload']:
                self._dump_payload(logs[0], rule_set, opts['dump_payload'])
        finally:
            analyzer._get_cached_rule_buckets = original_get_buckets

        if opts['save']:
            with open(opts['save'], 'w', encoding='utf-8') as handle:
                json.dump(saved, handle)
            self.stdout.write(f'\nSaved per-line results to {opts["save"]}')
        if opts['compare']:
            self._compare(saved, opts['compare'])

    # -- selection --

    def _select_logs(self, opts):
        if opts['upload_id']:
            return list(UploadedLog.objects.filter(upload_id__in=opts['upload_id']))
        logs = []
        seen = set()
        for log in UploadedLog.objects.annotate(size=Length('content')).order_by('-size', 'upload_id'):
            digest = hashlib.sha1((log.content or '').encode('utf-8', 'replace')).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            logs.append(log)
            if len(logs) >= opts['largest']:
                break
        return logs

    # -- timing --

    def _benchmark_log(self, log, buckets, rule_set, runs):
        # The same line selection analyze_log_text makes.
        lines = [ln.strip() for ln in (log.content or '').splitlines() if ln.strip()]
        self.stdout.write('')
        self.stdout.write(self.style.MIGRATE_HEADING(f'{log.upload_id}: {len(lines)} lines'))

        # Matching dominates and does not depend on how results are presented, so
        # it is timed once; the rest of the per-line work is cheap enough to repeat
        # until it is measured reliably.
        start = time.perf_counter()
        matches = {}
        for line in lines:
            if line not in matches:
                matches[line] = analyzer._collect_effective_and_shadowed_matches_for_line(line, buckets)
        match_seconds = time.perf_counter() - start

        # Everything _analyze_single_line does besides matching, measured by
        # replaying the matches just computed.
        per_line = []
        original_collect = analyzer._collect_effective_and_shadowed_matches_for_line
        analyzer._collect_effective_and_shadowed_matches_for_line = (
            lambda line, _buckets, exclude_rule_id=None: matches[line]
        )
        try:
            for run in range(runs + 1):
                start = time.perf_counter()
                for line in lines:
                    analyzer._analyze_single_line(line, buckets)
                if run:  # run 0 is the warm-up
                    per_line.append(time.perf_counter() - start)
        finally:
            analyzer._collect_effective_and_shadowed_matches_for_line = original_collect

        start = time.perf_counter()
        payload = analyzer.analyze_log_text(log.content or '', rule_set)
        total_seconds = time.perf_counter() - start

        dumps = []
        for run in range(runs + 1):
            start = time.perf_counter()
            encoded = json.dumps(payload)
            if run:
                dumps.append(time.perf_counter() - start)

        self.stdout.write(f'  {"matching":<28}: {match_seconds * 1000:9.1f} ms')
        for label, values in (('per-line work w/o matching', per_line), ('json.dumps', dumps)):
            self.stdout.write(
                f'  {label:<28}: min {min(values) * 1000:9.1f} ms   '
                f'median {statistics.median(values) * 1000:9.1f} ms'
            )
        self.stdout.write(f'  {"analyze_log_text total":<28}: {total_seconds * 1000:9.1f} ms   '
                          f'({len(lines) / total_seconds:.0f} lines/s)')

        self._report_payload(payload, encoded)
        return [self._line_signature(entry) for entry in payload['lines']]

    def _report_payload(self, payload, encoded):
        lines = payload['lines']
        self.stdout.write(f'  {"payload JSON":<28}: {len(encoded) / 1024:9.1f} KiB '
                          f'({len(encoded) / max(len(lines), 1):.0f} bytes/line)')
        key_bytes = {}
        for entry in lines:
            for key, value in entry.items():
                key_bytes[key] = key_bytes.get(key, 0) + len(json.dumps({key: value})) - 2
        top = sorted(key_bytes.items(), key=lambda item: -item[1])
        self.stdout.write('  bytes per key: ' + ', '.join(f'{k}={v / 1024:.0f}K' for k, v in top))

        spans = [len(self._line_signature(entry)['spans']) for entry in lines]
        coloured = [n for n in spans if n]
        partial_lines = sum(1 for entry in lines if entry.get('css_class') == 'status-unknown'
                            and entry.get('dominant_status', '?') != '?')
        self.stdout.write(
            f'  lines with spans: {len(coloured)}   spans max {max(spans, default=0)} '
            f'avg {statistics.mean(coloured) if coloured else 0:.2f}   '
            f'matched lines without a line colour: {partial_lines}   '
            f'unlocated fallback paths: {self._unlocated_fallback_paths(lines)}'
        )

    @staticmethod
    def _unlocated_fallback_paths(lines):
        count = 0
        for entry in lines:
            if 'fallback_only' in entry:
                if entry['fallback_only'] and not any(
                    span.get('priority') == 1 for span in entry.get('highlights') or []
                ):
                    count += 1
            else:
                highlight = entry.get('filepath_highlight')
                if highlight and 'start' not in highlight:
                    count += 1
        return count

    @staticmethod
    def _line_signature(entry):
        """Verdict plus colouring of one analyzed line, in a version-neutral shape."""
        spans = []
        if 'highlights' in entry:
            spans = [(h['start'], h['end'], h['status']) for h in entry['highlights'] or []]
        else:
            highlight = entry.get('filepath_highlight')
            if highlight and 'start' in highlight:
                spans.append((highlight['start'], highlight['end'], highlight['status']))
            spans.extend((h['start'], h['end'], h['status']) for h in entry.get('substring_highlights') or [])
        return {
            'verdict': [entry.get('dominant_status'), entry.get('status_codes'), entry.get('entry_type'),
                        entry.get('matcher'), entry.get('reasons')],
            'css_class': entry.get('css_class'),
            'spans': sorted(spans),
        }

    # -- extras --

    def _profile(self, log, rule_set):
        self.stdout.write('')
        self.stdout.write(self.style.MIGRATE_HEADING(f'cProfile of analyze_log_text on {log.upload_id}'))
        profiler = cProfile.Profile()
        profiler.enable()
        analyzer.analyze_log_text(log.content or '', rule_set)
        profiler.disable()
        out = io.StringIO()
        pstats.Stats(profiler, stream=out).sort_stats('tottime').print_stats(25)
        self.stdout.write(out.getvalue())

    def _dump_payload(self, log, rule_set, path):
        payload = analyzer.analyze_log_text(log.content or '', rule_set)
        with open(path, 'w', encoding='utf-8') as handle:
            # A string literal, so the page can time JSON.parse itself.
            handle.write('window.BENCH_PAYLOAD_TEXT = ')
            handle.write(json.dumps(json.dumps(payload)))
            handle.write(';\n')
        self.stdout.write(f'\nWrote payload of {log.upload_id} to {path}')

    def _compare(self, current, path):
        with open(path, encoding='utf-8') as handle:
            previous = json.load(handle)
        self.stdout.write('')
        self.stdout.write(self.style.MIGRATE_HEADING(f'Comparison with {path}'))
        for upload_id, lines in current.items():
            before = previous.get(upload_id)
            if before is None:
                self.stdout.write(f'  {upload_id}: not in the saved results')
                continue
            if len(before) != len(lines):
                self.stdout.write(f'  {upload_id}: line count differs ({len(before)} vs {len(lines)})')
                continue
            verdicts = css = spans = 0
            for old, new in zip(before, lines):
                verdicts += old['verdict'] != new['verdict']
                css += old['css_class'] != new['css_class']
                spans += [list(s) for s in old['spans']] != [list(s) for s in new['spans']]
            style = self.style.SUCCESS if verdicts == 0 else self.style.ERROR
            self.stdout.write(style(
                f'  {upload_id}: verdict mismatches {verdicts}   '
                f'line colour changes {css}   span changes {spans}'
            ))
