import re
import time

from django.core.management.base import BaseCommand

from fixlist import analyzer
from fixlist.models import ClassificationRule, UploadedLog
from fixlist.rule_sets import SHARED_RULE_SET_KEY


# Short adversarial inputs. Catastrophic patterns blow up at small sizes;
# keeping inputs small bounds the worst-case wall time of this command.
ADVERSARIAL_INPUTS = [
    ("a200",            "a" * 200),
    ("a200_X",          "a" * 200 + "X"),
    ("ab100",           "ab" * 100),
    ("ab100_X",         "ab" * 100 + "X"),
    ("slash200",        ("\\" + "a") * 100),
    ("space200",        ("a " * 100)),
    ("digit200",        "1" * 200),
    ("path200",         "C:\\Users\\" + "a" * 180 + "\\file.exe"),
    ("mixed200",        ("aA1\\ " * 50)),
]


class Command(BaseCommand):
    help = (
        'Benchmark regex classification rules to find ones susceptible to catastrophic '
        'backtracking. Reports rules that fall back to stdlib re (i.e. were rejected by '
        're2) and times each against a set of adversarial inputs. Optionally times them '
        'against a real uploaded log via --upload-id.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--upload-id',
            help='Also time each fallback regex against this UploadedLog\'s content '
                 '(per line). Use to reproduce a specific incident.',
        )
        parser.add_argument(
            '--threshold-ms',
            type=float,
            default=50.0,
            help='Flag any single regex.search() call that exceeds this many milliseconds '
                 '(default: 50).',
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=0,
            help='Only benchmark the first N fallback rules (0 = all). Useful to sanity-check '
                 'before running on a large rule set.',
        )

    def handle(self, *args, **opts):
        buckets = analyzer._get_cached_rule_buckets(SHARED_RULE_SET_KEY)

        fallback = buckets[ClassificationRule.MATCH_REGEX]
        re2_rules = buckets.get('__regex_set_rules') or []

        total_regex_rules = ClassificationRule.objects.filter(
            match_type=ClassificationRule.MATCH_REGEX,
            is_enabled=True,
        ).count()

        self.stdout.write(self.style.MIGRATE_HEADING('Regex rule inventory'))
        self.stdout.write(f'  enabled regex rules in DB : {total_regex_rules}')
        self.stdout.write(f'  accepted by re2 (fast set): {len(re2_rules)}')
        self.stdout.write(f'  fallback to stdlib re     : {len(fallback)}  <-- catastrophic-backtracking candidates')
        self.stdout.write('')

        if not fallback:
            self.stdout.write(self.style.SUCCESS(
                'No fallback rules. All regex rules use re2; catastrophic backtracking is '
                'not possible from rule patterns.'
            ))
            return

        rules_to_benchmark = fallback if opts['limit'] == 0 else fallback[:opts['limit']]
        threshold_s = opts['threshold_ms'] / 1000.0

        self.stdout.write(self.style.MIGRATE_HEADING(
            f'Benchmarking {len(rules_to_benchmark)} fallback rule(s) against '
            f'{len(ADVERSARIAL_INPUTS)} adversarial input(s)'
        ))

        results = []
        for rule, compiled in rules_to_benchmark:
            worst_label = ''
            worst_time = 0.0
            total_time = 0.0
            for label, payload in ADVERSARIAL_INPUTS:
                elapsed = _time_search(compiled, payload)
                total_time += elapsed
                if elapsed > worst_time:
                    worst_time = elapsed
                    worst_label = label
            results.append({
                'rule': rule,
                'worst_time': worst_time,
                'worst_label': worst_label,
                'total_time': total_time,
            })

        results.sort(key=lambda r: -r['worst_time'])

        self.stdout.write('')
        self.stdout.write(self.style.MIGRATE_HEADING('Top slowest patterns (worst single input)'))
        for r in results[:20]:
            rule = r['rule']
            flag = ' [SLOW]' if r['worst_time'] >= threshold_s else ''
            self.stdout.write(
                f'  {r["worst_time"]*1000:8.2f} ms  on {r["worst_label"]:<10s}  '
                f'id={rule.id}  status={rule.status}  '
                f'pattern={_truncate(rule.source_text, 100)!r}{flag}'
            )

        flagged = [r for r in results if r['worst_time'] >= threshold_s]
        if flagged:
            self.stdout.write('')
            self.stdout.write(self.style.WARNING(
                f'{len(flagged)} rule(s) exceeded {opts["threshold_ms"]}ms on at least one '
                f'adversarial input. Inspect their patterns for nested quantifiers '
                f'(e.g. "(.+)+", "(a|a)*"), greedy alternation, or unbounded lookaround.'
            ))

        upload_id = opts.get('upload_id')
        if upload_id:
            self.stdout.write('')
            self.stdout.write(self.style.MIGRATE_HEADING(
                f'Replaying fallback rules against UploadedLog upload_id={upload_id}'
            ))
            try:
                log = UploadedLog.objects.get(upload_id=upload_id)
            except UploadedLog.DoesNotExist:
                self.stderr.write(f'  no upload with upload_id={upload_id}')
                return
            lines = [ln.strip() for ln in (log.content or '').splitlines() if ln.strip()]
            self.stdout.write(f'  log has {len(lines)} non-empty lines')

            per_rule_total = []
            for rule, compiled in rules_to_benchmark:
                start = time.perf_counter()
                worst_line_time = 0.0
                worst_line = ''
                for ln in lines:
                    t = _time_search(compiled, ln)
                    if t > worst_line_time:
                        worst_line_time = t
                        worst_line = ln
                total = time.perf_counter() - start
                per_rule_total.append({
                    'rule': rule,
                    'total': total,
                    'worst_line_time': worst_line_time,
                    'worst_line': worst_line,
                })

            per_rule_total.sort(key=lambda r: -r['total'])
            self.stdout.write('')
            self.stdout.write(self.style.MIGRATE_HEADING('Top time spent per rule across the log'))
            for r in per_rule_total[:20]:
                rule = r['rule']
                self.stdout.write(
                    f'  {r["total"]*1000:9.1f} ms total   worst-line {r["worst_line_time"]*1000:7.2f} ms   '
                    f'id={rule.id}  pattern={_truncate(rule.source_text, 80)!r}'
                )
                if r['worst_line_time'] >= threshold_s:
                    self.stdout.write(f'      worst line: {_truncate(r["worst_line"], 200)!r}')


def _time_search(compiled, payload):
    start = time.perf_counter()
    try:
        compiled.search(payload)
    except re.error:
        pass
    return time.perf_counter() - start


def _truncate(s, n):
    if s is None:
        return ''
    if len(s) <= n:
        return s
    return s[:n] + '...'
