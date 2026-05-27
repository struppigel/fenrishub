"""Tests for the DB-backed log type detection (seeded built-in rules + custom rules)."""

from django.core.exceptions import ValidationError
from django.test import TestCase

from fixlist.models import LogTypeDetectionRule, UploadedLog, detect_log_type


class BuiltinSeedDetectionTests(TestCase):
    """Verifies the migration's seeded built-in rules match real samples."""

    def test_english_frst_and_addition(self):
        self.assertEqual(detect_log_type('Scan result of Farbar Recovery Scan Tool\n...'), 'FRST')
        self.assertEqual(detect_log_type('Additional scan result of Farbar Recovery Scan Tool\n...'), 'Addition')

    def test_composite_frst_and_addition(self):
        content = (
            'Scan result of Farbar Recovery Scan Tool\nfirst part\n'
            'Additional scan result of Farbar Recovery Scan Tool\nsecond part'
        )
        self.assertEqual(detect_log_type(content), 'FRST&Addition')

    def test_fixlog(self):
        self.assertEqual(detect_log_type('Fix result of Farbar Recovery Scan Tool\nfoo'), 'Fixlog')

    def test_german_frst(self):
        content = (
            'Untersuchungsergebnis von Farbar Recovery Scan Tool (FRST) (x64) Version: 28-04-2026\n'
            'durchgeführt von Ryuuga (Administrator) auf DESKTOP-QBABUGT\n'
        )
        self.assertEqual(detect_log_type(content), 'FRST')

    def test_german_addition(self):
        content = 'Zusätzliches Untersuchungsergebnis von Farbar Recovery Scan Tool (x64) Version: 28-04-2026\n'
        self.assertEqual(detect_log_type(content), 'Addition')

    def test_spanish_frst(self):
        content = 'Resultado del análisis realizado por Farbar Recovery Scan Tool (FRST) (x64) Versión: 28-04-2026\n'
        self.assertEqual(detect_log_type(content), 'FRST')

    def test_spanish_addition(self):
        content = 'Resultados del Análisis Adicional de Farbar Recovery Scan Tool (x64) Versión: 28-04-2026\n'
        self.assertEqual(detect_log_type(content), 'Addition')

    def test_french_frst(self):
        content = "Résultats d'analyse de  Farbar Recovery Scan Tool (FRST) (x64) Version: 14-05-2026\n"
        self.assertEqual(detect_log_type(content), 'FRST')

    def test_french_addition(self):
        content = "Résultats de l'Analyse supplémentaire de Farbar Recovery Scan Tool (x64) Version: 14-05-2026\n"
        self.assertEqual(detect_log_type(content), 'Addition')

    def test_polish_frst(self):
        content = 'Rezultaty skanowania Farbar Recovery Scan Tool (FRST) (x64) Wersja: 28-04-2026\n'
        self.assertEqual(detect_log_type(content), 'FRST')

    def test_polish_addition(self):
        content = 'Rezultaty skanu uzupełniającego Farbar Recovery Scan Tool (x64) Wersja: 28-04-2026\n'
        self.assertEqual(detect_log_type(content), 'Addition')

    def test_dutch_frst(self):
        content = 'Scanresultaten van Farbar Recovery Scan Tool (FRST) (x64) Versie: 15-05-2026\n'
        self.assertEqual(detect_log_type(content), 'FRST')

    def test_dutch_addition(self):
        content = 'Extra scanresultaten van Farbar Recovery Scan Tool (x64) Versie: 15-05-2026\n'
        self.assertEqual(detect_log_type(content), 'Addition')

    def test_portuguese_frst(self):
        content = 'Resultado do análise da Farbar Recovery Scan Tool (FRST) (x64) Versão: 28-04-2026\n'
        self.assertEqual(detect_log_type(content), 'FRST')

    def test_portuguese_addition(self):
        content = 'Resultado da análise adicional Farbar Recovery Scan Tool (x64) Versão: 28-04-2026\n'
        self.assertEqual(detect_log_type(content), 'Addition')

    def test_chinese_frst(self):
        content = '关于...的扫描结果 Farbar Recovery Scan Tool (FRST) (x64) 版本: 28-04-2026\n'
        self.assertEqual(detect_log_type(content), 'FRST')

    def test_chinese_addition(self):
        content = '额外的扫描结果 Farbar Recovery Scan Tool (x64) 版本: 28-04-2026\n'
        self.assertEqual(detect_log_type(content), 'Addition')

    def test_russian_frst(self):
        content = 'Результат сканирования Farbar Recovery Scan Tool (FRST) (x64) Версия: 28-04-2026\n'
        self.assertEqual(detect_log_type(content), 'FRST')

    def test_frst_shortcut(self):
        content = 'Users shortcut scan result (x64) Version: 16-05-2026\nRan by Wes\n'
        self.assertEqual(detect_log_type(content), 'Shortcut')

    def test_hitmanpro(self):
        content = (
            '[code]\nHitmanPro 3.8.50.346\nwww.hitmanpro.com\n\n'
            '   Computer name . . . . : LAPTOP\n'
        )
        self.assertEqual(detect_log_type(content), 'HitmanPro')

    def test_adwcleaner(self):
        content = (
            '# -------------------------------\n'
            '# Malwarebytes AdwCleaner 8.5.0.595\n'
            '# -------------------------------\n'
        )
        self.assertEqual(detect_log_type(content), 'AdwCleaner')

    def test_emsisoft(self):
        content = 'Emsisoft Emergency Kit - Version 2025.7\nLast update: N/A\n'
        self.assertEqual(detect_log_type(content), 'Emsisoft')

    def test_malwarebytes_threat_scan(self):
        content = (
            'Malwarebytes\nwww.malwarebytes.com\n\n'
            '-Log Details-\nScan Date: 5/12/2026\n'
        )
        self.assertEqual(detect_log_type(content), 'Malwarebytes')

    def test_eset_english(self):
        content = (
            '5/15/2026 11:20:04 AM\n'
            'Scanned files: 1351708\n'
            'Detected files: 9\n'
            'Cleaned files: 9\n'
            'Total scan time 01:30:29\n'
            'Scan status: Finished\n'
        )
        self.assertEqual(detect_log_type(content), 'ESET')

    def test_unknown_for_random_paste(self):
        self.assertEqual(detect_log_type('https://paste.centos.org/view/3f94ab3e'), 'Unknown')
        self.assertEqual(detect_log_type('lealalaa'), 'Unknown')
        self.assertEqual(detect_log_type(''), 'Unknown')


class CustomRuleDetectionTests(TestCase):
    def test_custom_rule_match_is_picked_up_immediately(self):
        self.assertEqual(detect_log_type('Custom marker line\nbody'), 'Unknown')
        LogTypeDetectionRule.objects.create(
            name='Custom test rule',
            log_type='HitmanPro',
            pattern=r'^Custom marker line',
            scope=LogTypeDetectionRule.SCOPE_START,
            priority=5,
        )
        self.assertEqual(detect_log_type('Custom marker line\nbody'), 'HitmanPro')

    def test_disabling_a_rule_stops_matches(self):
        rule = LogTypeDetectionRule.objects.create(
            name='Toggle test',
            log_type='AdwCleaner',
            pattern=r'^Toggle marker',
            scope=LogTypeDetectionRule.SCOPE_START,
            priority=5,
        )
        self.assertEqual(detect_log_type('Toggle marker\nbody'), 'AdwCleaner')
        rule.is_enabled = False
        rule.save()
        self.assertEqual(detect_log_type('Toggle marker\nbody'), 'Unknown')

    def test_deleting_a_rule_stops_matches(self):
        rule = LogTypeDetectionRule.objects.create(
            name='Delete test',
            log_type='Emsisoft',
            pattern=r'^Delete marker',
            scope=LogTypeDetectionRule.SCOPE_START,
            priority=5,
        )
        self.assertEqual(detect_log_type('Delete marker\n...'), 'Emsisoft')
        rule.delete()
        self.assertEqual(detect_log_type('Delete marker\n...'), 'Unknown')

    def test_priority_breaks_ties_to_lower_first(self):
        LogTypeDetectionRule.objects.create(
            name='Higher priority',
            log_type='ESET',
            pattern=r'^AMBIGUOUS marker',
            scope=LogTypeDetectionRule.SCOPE_START,
            priority=1,
        )
        LogTypeDetectionRule.objects.create(
            name='Lower priority',
            log_type='HitmanPro',
            pattern=r'^AMBIGUOUS marker',
            scope=LogTypeDetectionRule.SCOPE_START,
            priority=50,
        )
        self.assertEqual(detect_log_type('AMBIGUOUS marker\nfoo'), 'ESET')


class LogTypeDetectionRuleModelTests(TestCase):
    def test_clean_rejects_invalid_regex(self):
        rule = LogTypeDetectionRule(
            name='Bad regex',
            log_type='FRST',
            pattern='(unclosed',
            scope=LogTypeDetectionRule.SCOPE_FULL,
        )
        with self.assertRaises(ValidationError) as cm:
            rule.full_clean()
        self.assertIn('pattern', cm.exception.message_dict)

    def test_clean_rejects_empty_pattern(self):
        rule = LogTypeDetectionRule(
            name='Empty regex',
            log_type='FRST',
            pattern='   ',
            scope=LogTypeDetectionRule.SCOPE_FULL,
        )
        with self.assertRaises(ValidationError):
            rule.full_clean()


class UploadedLogReclassificationTests(TestCase):
    def test_recalculate_log_type_uses_db_rules(self):
        log = UploadedLog.objects.create(
            upload_id='test-localized',
            forum_username='u',
            original_filename='FRST.txt',
            content='Untersuchungsergebnis von Farbar Recovery Scan Tool (FRST) (x64)\n',
        )
        log.recalculate_log_type()
        log.refresh_from_db()
        self.assertEqual(log.log_type, 'FRST')
