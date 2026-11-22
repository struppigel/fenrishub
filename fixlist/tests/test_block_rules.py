"""Rules that match a whole block (match_unit "block"): what a block rule
tests (the block's lines joined by line breaks, its entries and paths), and
that its verdict reaches every line of the block, by priority."""

from .. import frst_extractors as ex
from ..analyzer import analyze_log_text, inspect_line_matches, invalidate_rule_buckets_cache, parse_rule_line
from ..fact_service import ConditionSpec, condition_key_for, set_rule_conditions
from ..models import ClassificationRule, Fact, FactRule, FactTagSource, RuleCondition, RuleTag
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase
from . import spor7_sample as sample

B = ClassificationRule.STATUS_MALWARE
C = ClassificationRule.STATUS_CLEAN
P = ClassificationRule.STATUS_PUP
BLOCK = ClassificationRule.MATCH_UNIT_BLOCK

SPOR = "\n".join([
    "==================== Spor 0.7.1 - forensic triage log ====================",
    "==================== PERSISTENCE - autostarts ====================",
    *sample.TASK_BLOCK,
    "2026-11-20 08:15:02 [task] \\Microsoft\\Windows\\Defrag",
    "    program: C:\\Windows\\System32\\defrag.exe",
])
# banner, banner, task, program, arguments, info, other task, its program
TASK_LINES = slice(2, 6)

SERVICE = r"S2 AVP; C:\Program Files\Kaspersky\avp.exe [123 2026-01-01] (Kaspersky -> Kaspersky)"


class BlockRuleTests(LogAnalyzerApiBaseTestCase):
    def _rule(self, source_text, status=B, match_type=ClassificationRule.MATCH_SUBSTRING, **overrides):
        overrides.setdefault("match_unit", BLOCK)
        return ClassificationRule.objects.create(
            owner=self.user, status=status, match_type=match_type, source_text=source_text,
            all_log_types=True, **overrides,
        )

    def _statuses(self, text=SPOR, log_type="Spor"):
        return [line["dominant_status"] for line in analyze_log_text(text, log_type=log_type)["lines"]]

    def test_a_regex_spans_the_lines_of_its_block(self):
        self._rule(r"\[task\] .*\n^program: .*\\AppData\\Roaming\\", match_type=ClassificationRule.MATCH_REGEX)
        self.assertEqual(self._statuses(), ["?", "?", B, B, B, B, "?", "?"])

    def test_dollar_and_caret_stand_for_each_line(self):
        self._rule(r"^arguments: /run$", match_type=ClassificationRule.MATCH_REGEX)
        self.assertEqual(self._statuses()[TASK_LINES], [B, B, B, B])

    def test_an_exact_rule_compares_the_whole_block(self):
        text = "\n".join(line.strip() for line in sample.TASK_BLOCK)
        self._rule(text, match_type=ClassificationRule.MATCH_EXACT)
        self.assertEqual(self._statuses()[TASK_LINES], [B, B, B, B])
        ClassificationRule.objects.all().delete()
        invalidate_rule_buckets_cache()
        # The block's first line alone is not the block.
        self._rule(sample.TASK_BLOCK[0], match_type=ClassificationRule.MATCH_EXACT)
        self.assertEqual(self._statuses()[TASK_LINES], ["?", "?", "?", "?"])

    def test_a_file_path_on_any_line(self):
        self._rule(sample.TASK_PROGRAM, match_type=ClassificationRule.MATCH_FILEPATH,
                   filepath=sample.TASK_PROGRAM, normalized_filepath=ex.path_key(sample.TASK_PROGRAM))
        self.assertEqual(self._statuses()[TASK_LINES], [B, B, B, B])

    def test_a_frst_parsed_rule_as_a_block_rule(self):
        rule_data = parse_rule_line(SERVICE, B)
        rule_data.pop("match_unit")
        self._rule(SERVICE, match_type=ClassificationRule.MATCH_PARSED_ENTRY,
                   **{key: rule_data[key] for key in ("entry_type", "name", "filepath", "filename", "company",
                                                      "normalized_filepath")})
        self.assertEqual(self._statuses(SERVICE + "\nother line", log_type="FRST"), [B, "?"])

    def test_priority_decides_each_line(self):
        self._rule("UpdateCheck", status=B)                                  # priority 7
        self._rule("arguments: /run", status=C, match_type=ClassificationRule.MATCH_EXACT,
                   match_unit="line")                                        # priority 19
        self.assertEqual(self._statuses()[TASK_LINES], [B, B, C, B])

    def test_a_frst_line_is_a_block_of_its_own(self):
        self._rule("Kaspersky")
        self.assertEqual(self._statuses(SERVICE + "\nother line", log_type="FRST"), [B, "?"])

    def test_conditional_block_rule(self):
        fact = Fact.objects.create(name="runs from Roaming")
        FactRule.objects.create(
            owner=self.user, fact=fact, match_type="substring", source_text="\\AppData\\Roaming\\", all_log_types=True,
        )
        specs = [ConditionSpec(fact.pk, RuleCondition.POLARITY_REQUIRE, RuleCondition.SCOPE_BLOCK)]
        rule = self._rule("[task]", status=P, condition_key=condition_key_for(specs))
        set_rule_conditions(rule, specs)
        # Only the task whose block holds the fact.
        self.assertEqual(self._statuses(), ["?", "?", P, P, P, P, "?", "?"])

    def test_tag_facts_on_every_line_of_the_block(self):
        tag = RuleTag.objects.create(name="evil task")
        rule = self._rule("UpdateCheck")
        rule.tags.add(tag)
        fact = Fact.objects.create(name="evil task found")
        FactTagSource.objects.create(fact=fact, tag=tag)
        [found] = analyze_log_text(SPOR, log_type="Spor")["facts"]
        self.assertEqual(found["line_indexes"], [2, 3, 4, 5])

    def test_inspect_with_and_without_its_block(self):
        self._rule("UpdateCheck")
        lines = [line.strip() for line in sample.TASK_BLOCK]
        program = lines[1]
        with_block = inspect_line_matches(program, log_type="Spor", block_lines=lines)
        self.assertEqual(with_block["dominant_status"], B)
        self.assertEqual(with_block["matches"][0]["match_unit"], BLOCK)
        self.assertEqual(inspect_line_matches(program, log_type="Spor")["dominant_status"], "?")
        self.assertEqual(inspect_line_matches(lines[0], log_type="Spor")["dominant_status"], B)
        rule_id = with_block["matches"][0]["id"]
        self.assertEqual(
            inspect_line_matches(program, log_type="Spor", block_lines=lines, exclude_rule_id=rule_id)["matches"], [],
        )

    def test_the_payload_names_the_blocks(self):
        lines = analyze_log_text(SPOR, log_type="Spor")["lines"]
        self.assertEqual([line.get("block_start") for line in lines], [None, None, 2, 2, 2, 2, 6, 6])
        self.assertEqual([line.get("block_entry_type") for line in lines[TASK_LINES]], ["spor_task"] * 4)
        # A sub-line has its block's parsed type.
        self.assertEqual(lines[3]["parsed_entry_type"], "spor_task")
