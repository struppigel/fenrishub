from django.db import IntegrityError, models
from django.db.models import Q
from django.db.models.signals import post_save, pre_delete
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.dispatch import receiver
import secrets
import string
import re

import mmh3
from django.utils import timezone

from .status_types import STATUS_CHOICES as _STATUS_CHOICES, STATUS_CSS_CLASS


PRIORITY_MIN = 0
PRIORITY_MAX = 20
DEFAULT_PRIORITY_BY_MATCH_TYPE = {
    'exact': 19,
    'parsed': 15,
    'filepath': 11,
    'substring': 7,
    'regex': 3,
}
PRIORITY_DEFAULT_LABELS = {
    DEFAULT_PRIORITY_BY_MATCH_TYPE['exact']: 'exact line',
    DEFAULT_PRIORITY_BY_MATCH_TYPE['parsed']: 'parsed entries',
    DEFAULT_PRIORITY_BY_MATCH_TYPE['filepath']: 'filepath',
    DEFAULT_PRIORITY_BY_MATCH_TYPE['substring']: 'substring',
    DEFAULT_PRIORITY_BY_MATCH_TYPE['regex']: 'regex',
}


def get_default_rule_owner_id():
    """Resolve a stable owner id for rules that are created without an explicit owner."""
    superuser = User.objects.filter(is_superuser=True).order_by('id').first()
    if superuser:
        return superuser.id

    fallback_user, _ = User.objects.get_or_create(
        username='rule_owner_fallback',
        defaults={
            'is_staff': True,
            'is_superuser': True,
        },
    )
    if not fallback_user.is_staff or not fallback_user.is_superuser:
        fallback_user.is_staff = True
        fallback_user.is_superuser = True
        fallback_user.save(update_fields=['is_staff', 'is_superuser'])
    if fallback_user.has_usable_password():
        fallback_user.set_unusable_password()
        fallback_user.save(update_fields=['password'])

    return fallback_user.id


class Fixlist(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fixlists')
    source_uploaded_log = models.ForeignKey('UploadedLog', on_delete=models.SET_NULL, null=True, blank=True, related_name='fixlists')
    username = models.CharField(max_length=255)
    content = models.TextField()
    internal_note = models.TextField(blank=True)
    download_count = models.PositiveIntegerField(default=0)
    share_token = models.CharField(max_length=32, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_public = models.BooleanField(default=True)
    deleted_at = models.DateTimeField(null=True, blank=True, default=None)
    line_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.username} by {self.owner.username}"

    def save(self, *args, **kwargs):
        if not self.share_token:
            self.share_token = self.generate_share_token()
        self.line_count = len([l for l in (self.content or '').splitlines() if l.strip()])
        super().save(*args, **kwargs)

    @staticmethod
    def generate_share_token():
        """Generate a random secure share token."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(32))


class UserProfile(models.Model):
    RULE_SET_MODE_SHARED = 'shared'
    RULE_SET_MODE_PRIVATE = 'private'
    RULE_SET_MODE_CHOICES = [
        (RULE_SET_MODE_SHARED, 'Shared'),
        (RULE_SET_MODE_PRIVATE, 'Private'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='fenris_profile')
    frst_fix_message = models.TextField(blank=True, default='')
    word_wrap = models.BooleanField(default=False)
    analyzer_fixlist_template = models.TextField(blank=True, default='')
    last_seen = models.DateTimeField(null=True, blank=True, db_index=True)
    rule_set_mode = models.CharField(
        max_length=16,
        choices=RULE_SET_MODE_CHOICES,
        default=RULE_SET_MODE_SHARED,
    )

    def __str__(self):
        return f'Profile for {self.user.username}'


class AccessLog(models.Model):
    fixlist = models.ForeignKey(Fixlist, on_delete=models.CASCADE, related_name='accesses')
    accessed_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        ordering = ['-accessed_at']

    def __str__(self):
        return f"Access to {self.fixlist.username} at {self.accessed_at}"


class SiteConfig(models.Model):
    """Singleton holding site-wide settings (e.g. the guest access token)."""

    guest_token = models.CharField(
        max_length=64,
        blank=True,
        default='',
        help_text='Shared secret for guest access to the log analyzer and help page. Leave blank to disable guest access entirely.',
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Site configuration'
        verbose_name_plural = 'Site configuration'

    def __str__(self):
        return 'Site configuration'

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        # Singleton: never delete.
        return

    @classmethod
    def get_solo(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    @classmethod
    def current_guest_token(cls):
        return (cls.get_solo().guest_token or '').strip()

    @staticmethod
    def generate_guest_token():
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(32))


MEMORABLE_ID_ADJECTIVES = [
    'amber', 'ancient', 'arcane', 'ardent', 'async', 'atomic', 'autumn', 'azure', 'balmy',
    'blazing', 'blessed', 'bold', 'brave', 'bright', 'brisk', 'bronze', 'cached', 'calm',
    'candid', 'celestial', 'chained', 'charged', 'chilly', 'chosen', 'clever', 'cobalt',
    'compact', 'copper', 'coral', 'cosmic', 'crafted', 'crimson', 'crisp', 'cunning', 'curious',
    'cursed', 'dappled', 'daring', 'desert', 'dewy', 'digital', 'distant', 'divine', 'dreamy',
    'dusky', 'dynamic', 'eager', 'earnest', 'elite', 'ember', 'emerald', 'enchanted', 'encoded',
    'epic', 'fabled', 'fair', 'faithful', 'fancy', 'feral', 'fertile', 'fierce', 'fluffy',
    'fond', 'forged', 'frenzied', 'fresh', 'friendly', 'frosty', 'frozen', 'gallant', 'gentle',
    'gilded', 'glad', 'glassy', 'gleaming', 'glitched', 'glossy', 'glowing', 'golden',
    'graceful', 'grand', 'happy', 'hardy', 'hashed', 'haunted', 'heroic', 'hidden', 'hollow',
    'honest', 'humble', 'icy', 'idle', 'indexed', 'indigo', 'jade', 'jagged', 'jolly', 'joyful',
    'keen', 'lazy', 'leafy', 'lilac', 'linked', 'live', 'lively', 'loyal', 'lucid', 'lucky',
    'lunar', 'lush', 'majestic', 'master', 'mellow', 'merry', 'meta', 'mighty', 'mild',
    'mindful', 'misty', 'modest', 'mossy', 'mystic', 'neat', 'neon', 'nested', 'nimble',
    'noble', 'ochre', 'olive', 'opal', 'packed', 'parallel', 'patched', 'peaceful', 'pearly',
    'pinned', 'piped', 'placid', 'plucky', 'polar', 'proud', 'pure', 'quick', 'quiet',
    'radiant', 'ranked', 'rapid', 'raw', 'retro', 'ripe', 'rosy', 'royal', 'runic', 'rustic',
    'sandy', 'savage', 'savvy', 'scarlet', 'scoped', 'secret', 'serene', 'sharp', 'shiny',
    'signed', 'silent', 'silken', 'silver', 'sleek', 'slow', 'small', 'smoky', 'snowy', 'soft',
    'solar', 'southern', 'sparse', 'spectral', 'spirited', 'spry', 'stable', 'static', 'steady',
    'stealth', 'stellar', 'stoic', 'stormy', 'strict', 'sturdy', 'sublime', 'sunny', 'sweet',
    'swift', 'synced', 'tagged', 'tame', 'tender', 'tidal', 'tidy', 'tiny', 'traced',
    'tranquil', 'true', 'turquoise', 'typed', 'unpacked', 'valiant', 'vectored', 'velvet',
    'verdant', 'violet', 'virtual', 'vivid', 'warm', 'weathered', 'western', 'wild', 'windy',
    'winged', 'wintry', 'wired', 'wise', 'witty', 'woven', 'wrapped', 'wry', 'young', 'zealous',
    'zipped',
]

MEMORABLE_ID_NOUNS = [
    'ace', 'acorn', 'amulet', 'anchor', 'android', 'arena', 'arrow', 'artifact', 'aspen',
    'aurora', 'avatar', 'axe', 'badge', 'badger', 'banner', 'base', 'bay', 'beach', 'beacon',
    'bear', 'bee', 'beech', 'berry', 'binary', 'birch', 'blade', 'blob', 'bloom', 'blossom',
    'boot', 'boss', 'boulder', 'bow', 'breeze', 'briar', 'bridge', 'brook', 'buffer',
    'bumblebee', 'byte', 'cache', 'canyon', 'cape', 'captain', 'cascade', 'castle', 'cavern',
    'cedar', 'champion', 'cherry', 'chestnut', 'cipher', 'citadel', 'clan', 'cloak', 'cloud',
    'clover', 'coast', 'codec', 'combo', 'comet', 'cove', 'creek', 'crest', 'crow', 'crown',
    'crypt', 'cursor', 'cypress', 'daemon', 'dagger', 'daisy', 'dale', 'dawn', 'deck', 'decoy',
    'deer', 'delta', 'dice', 'dolphin', 'dove', 'dragon', 'driver', 'drone', 'dune', 'dungeon',
    'eagle', 'echo', 'elk', 'elm', 'engine', 'equinox', 'falcon', 'fawn', 'fern', 'field',
    'flame', 'flint', 'forest', 'fox', 'frame', 'frost', 'garden', 'gauntlet', 'gem', 'glacier',
    'glade', 'glen', 'glitch', 'glyph', 'granite', 'graph', 'grove', 'guild', 'gust', 'hammer',
    'harbor', 'hare', 'harvest', 'hash', 'hawk', 'hazel', 'heap', 'heath', 'hero', 'heron',
    'hill', 'holly', 'hook', 'horizon', 'host', 'iris', 'island', 'jungle', 'juniper', 'kernel',
    'kestrel', 'knight', 'knoll', 'lagoon', 'lake', 'lance', 'lantern', 'lark', 'laser',
    'lattice', 'legion', 'level', 'lexer', 'lily', 'lime', 'loader', 'loop', 'loot', 'lynx',
    'macro', 'mage', 'magnolia', 'maple', 'marsh', 'matrix', 'meadow', 'mech', 'mesa', 'mesh',
    'meteor', 'midnight', 'mink', 'mirror', 'mist', 'module', 'moon', 'moose', 'moss',
    'mountain', 'mulberry', 'mustang', 'nebula', 'nest', 'node', 'nova', 'oak', 'oasis',
    'ocean', 'orbit', 'orchard', 'otter', 'owl', 'packet', 'panda', 'panther', 'parser',
    'party', 'patch', 'pawn', 'peach', 'peak', 'pebble', 'pelican', 'petal', 'phoenix',
    'pilot', 'pine', 'pixel', 'planet', 'plum', 'pointer', 'pond', 'poppy', 'port', 'potion',
    'prairie', 'prompt', 'proxy', 'quail', 'quartz', 'query', 'quest', 'queue', 'quiver',
    'rabbit', 'raid', 'ranger', 'raster', 'raven', 'realm', 'reef', 'registry', 'relic',
    'render', 'ridge', 'ripple', 'river', 'robot', 'rocket', 'rose', 'rune', 'runtime',
    'saber', 'sable', 'sage', 'sandbox', 'sapling', 'scanner', 'schema', 'scout', 'script',
    'scroll', 'sea', 'seal', 'sensor', 'sentinel', 'shader', 'shell', 'shield', 'shore',
    'sigil', 'signal', 'sky', 'socket', 'sparrow', 'spire', 'spring', 'sprite', 'spruce',
    'squad', 'squirrel', 'stack', 'stage', 'star', 'stream', 'struct', 'summit', 'sunrise',
    'sunset', 'swallow', 'swan', 'switch', 'sword', 'sycamore', 'symbol', 'syntax', 'thread',
    'throne', 'thunder', 'tide', 'tile', 'timber', 'token', 'tower', 'trace', 'trail',
    'trophy', 'tundra', 'turtle', 'vale', 'valley', 'vault', 'vector', 'vertex', 'vine',
    'vista', 'volcano', 'voyage', 'walrus', 'wand', 'warrior', 'wave', 'whale', 'wharf',
    'widget', 'willow', 'wisp', 'wizard', 'wolf', 'woodland', 'zephyr',
]


def generate_memorable_upload_id():
    adjective = secrets.choice(MEMORABLE_ID_ADJECTIVES)
    noun = secrets.choice(MEMORABLE_ID_NOUNS)
    return f'{adjective}-{noun}'


def generate_infection_case_id():
    return f"ic-{secrets.token_hex(4)}"


class ClassificationRule(models.Model):
    STATUS_MALWARE = 'B'
    STATUS_PUP = 'P'
    STATUS_CLEAN = 'C'
    STATUS_WARNING = '!'
    STATUS_ALERT = 'A'
    STATUS_GRAYWARE = 'G'
    STATUS_SECURITY = 'S'
    STATUS_INFO = 'I'
    STATUS_JUNK = 'J'
    STATUS_UNKNOWN = '?'

    STATUS_CHOICES = _STATUS_CHOICES

    # Statuses a user can assign when creating or editing a rule.
    # `?` (Unknown) is the default for unmatched lines, not a meaningful classification.
    CREATABLE_STATUS_CHOICES = [
        (code, label) for code, label in STATUS_CHOICES if code != '?'
    ]

    STATUS_CSS_CLASS_MAP = STATUS_CSS_CLASS

    MATCH_EXACT = 'exact'
    MATCH_SUBSTRING = 'substring'
    MATCH_REGEX = 'regex'
    MATCH_FILEPATH = 'filepath'
    MATCH_PARSED_ENTRY = 'parsed'

    MATCH_TYPE_CHOICES = [
        (MATCH_EXACT, 'Exact line'),
        (MATCH_SUBSTRING, 'Substring'),
        (MATCH_REGEX, 'Regex'),
        (MATCH_FILEPATH, 'File path'),
        (MATCH_PARSED_ENTRY, 'Parsed'),
    ]

    status = models.CharField(max_length=1, choices=STATUS_CHOICES)
    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='classification_rules',
        default=get_default_rule_owner_id,
    )
    match_type = models.CharField(max_length=16, choices=MATCH_TYPE_CHOICES)
    source_text = models.TextField(help_text='Rule input without description metadata.')
    description = models.TextField(blank=True)
    source_name = models.CharField(max_length=128, blank=True)
    is_enabled = models.BooleanField(default=True)

    # Optional parsed metadata, populated for parsed/filepath rules.
    entry_type = models.CharField(max_length=64, blank=True)
    clsid = models.CharField(max_length=128, blank=True)
    name = models.CharField(max_length=512, blank=True)
    filepath = models.TextField(blank=True)
    normalized_filepath = models.TextField(blank=True)
    filename = models.CharField(max_length=260, blank=True)
    company = models.CharField(max_length=512, blank=True)
    arguments = models.TextField(blank=True)
    file_not_signed = models.BooleanField(default=False)
    attributes = models.CharField(max_length=16, blank=True)
    is_hidden = models.BooleanField(default=False)

    priority = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(PRIORITY_MIN), MaxValueValidator(PRIORITY_MAX)],
        db_index=True,
        help_text=(
            '0-20; higher wins. Lower priorities are entirely shadowed. '
            'Auto-set from match_type when blank.'
        ),
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-priority', 'status', 'match_type', 'source_text']
        unique_together = ('owner', 'status', 'match_type', 'source_text')
        constraints = [
            models.CheckConstraint(
                check=Q(priority__gte=PRIORITY_MIN) & Q(priority__lte=PRIORITY_MAX),
                name='classificationrule_priority_range',
            ),
        ]

    @property
    def status_css_class(self):
        return self.STATUS_CSS_CLASS_MAP.get(self.status, 'status-unknown')

    @classmethod
    def default_priority_for(cls, match_type: str) -> int:
        return DEFAULT_PRIORITY_BY_MATCH_TYPE.get(match_type, 10)

    def save(self, *args, **kwargs):
        if self.priority is None:
            self.priority = self.default_priority_for(self.match_type)
        super().save(*args, **kwargs)

    def __str__(self):
        owner_name = self.owner.username if self.owner_id else 'unknown'
        return f"{self.status} [{self.match_type}] p{self.priority} {self.source_text[:80]} ({owner_name})"


_FRST_MARKER = 'Scan result of Farbar Recovery Scan Tool'
_ADDITION_MARKER = 'Additional scan result of Farbar Recovery Scan Tool'
_FIXLIST_MARKER = 'Fix result of Farbar Recovery Scan Tool'


def detect_log_type(content: str) -> str:
    has_frst = _FRST_MARKER in content
    has_addition = _ADDITION_MARKER in content
    if has_frst and has_addition:
        return 'FRST&Addition'
    if has_frst:
        return 'FRST'
    if has_addition:
        return 'Addition'
    if content.lstrip().startswith(_FIXLIST_MARKER):
        return 'Fixlog'
    return 'Unknown'


_SCAN_DATE_RE = re.compile(r'Ran by .+\((\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\)')


def extract_scan_date(content: str):
    """Extract the scan datetime from a FRST/Addition/Fixlog header.

    Returns a datetime object or None.
    """
    from datetime import datetime as dt
    m = _SCAN_DATE_RE.search(content)
    if m:
        try:
            return dt.strptime(m.group(1), '%d-%m-%Y %H:%M:%S')
        except ValueError:
            return None
    return None


class UploadedLog(models.Model):
    LOG_TYPE_CHOICES = [
        ('FRST', 'FRST'),
        ('Addition', 'Addition'),
        ('FRST&Addition', 'FRST&Addition'),
        ('Fixlog', 'Fixlog'),
        ('Unknown', 'Unknown'),
    ]

    upload_id = models.CharField(max_length=64, unique=True, db_index=True)
    forum_username = models.CharField(max_length=100, db_index=True)
    original_filename = models.CharField(max_length=255)
    log_type = models.CharField(max_length=16, choices=LOG_TYPE_CHOICES, default='Unknown')
    is_incomplete = models.BooleanField(default=False)
    content = models.TextField()
    content_hash = models.CharField(max_length=32, blank=True, db_index=True)
    detected_encoding = models.CharField(max_length=32, blank=True, default='')
    created_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='uploaded_logs',
    )
    recipient_user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='received_uploaded_logs',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    scan_date = models.DateTimeField(null=True, blank=True, default=None)
    deleted_at = models.DateTimeField(null=True, blank=True, default=None)
    total_line_count = models.PositiveIntegerField(default=0)
    count_malware = models.PositiveIntegerField(default=0)
    count_pup = models.PositiveIntegerField(default=0)
    count_clean = models.PositiveIntegerField(default=0)
    count_alert = models.PositiveIntegerField(default=0)
    count_warning = models.PositiveIntegerField(default=0)
    count_grayware = models.PositiveIntegerField(default=0)
    count_security = models.PositiveIntegerField(default=0)
    count_info = models.PositiveIntegerField(default=0)
    count_junk = models.PositiveIntegerField(default=0)
    count_unknown = models.PositiveIntegerField(default=0)
    fixlog_total = models.PositiveIntegerField(default=0)
    fixlog_success = models.PositiveIntegerField(default=0)
    fixlog_not_found = models.PositiveIntegerField(default=0)
    fixlog_error = models.PositiveIntegerField(default=0)
    FIXLOG_STAT_FIELDS = ['fixlog_total', 'fixlog_success', 'fixlog_not_found', 'fixlog_error']
    ANALYSIS_STATUS_FIELD_MAP = {
        'B': 'count_malware',
        'P': 'count_pup',
        'C': 'count_clean',
        'A': 'count_alert',
        '!': 'count_warning',
        'G': 'count_grayware',
        'S': 'count_security',
        'I': 'count_info',
        'J': 'count_junk',
        '?': 'count_unknown',
    }

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.upload_id} ({self.forum_username})'

    def clean(self):
        username = (self.forum_username or '').strip()
        if not (1 <= len(username) <= 100):
            raise ValidationError({'forum_username': 'Username must be 1-100 characters.'})
        if not (self.content or '').strip():
            raise ValidationError({'content': 'Uploaded content cannot be empty.'})
        self.forum_username = username

    @staticmethod
    def compute_content_hash(content: str) -> str:
        raw = (content or '').encode('utf-8')
        return format(mmh3.hash128(raw, signed=False), '032x')

    def save(self, *args, **kwargs):
        self.clean()
        generated_upload_id = False
        if not self.upload_id:
            self.upload_id = self._generate_unique_upload_id()
            generated_upload_id = True
        self.content_hash = self.compute_content_hash(self.content)
        try:
            super().save(*args, **kwargs)
            return
        except IntegrityError as exc:
            if not (self._state.adding and generated_upload_id and 'upload_id' in str(exc).lower()):
                raise

        # A concurrent insert can still win between existence check and insert.
        # Retry a few times with a new generated id instead of surfacing a 500.
        for _ in range(5):
            self.upload_id = self._generate_unique_upload_id()
            try:
                super().save(*args, **kwargs)
                return
            except IntegrityError as retry_exc:
                if 'upload_id' not in str(retry_exc).lower():
                    raise

        raise IntegrityError('Could not persist UploadedLog after upload_id collision retries.')

    @property
    def effective_rule_set_label(self):
        """Short label for the rule set that `count_*` reflects ('shared' or 'private').

        Used by the uploads listing to show which rule set the displayed stats
        belong to. To avoid N+1 queries, callers should `select_related`
        `recipient_user__fenris_profile` on the queryset.
        """
        from .rule_sets import SHARED_RULE_SET_KEY, resolve_effective_rule_set_key
        return 'shared' if resolve_effective_rule_set_key(self) == SHARED_RULE_SET_KEY else 'private'

    @classmethod
    def analysis_stat_fields(cls):
        return ['total_line_count', *cls.ANALYSIS_STATUS_FIELD_MAP.values(), *cls.FIXLOG_STAT_FIELDS]

    @classmethod
    def analysis_stat_update_fields(cls):
        return [*cls.analysis_stat_fields(), 'updated_at']

    def apply_analysis_summary(self, summary: dict):
        summary_payload = summary if isinstance(summary, dict) else {}
        status_counts = summary_payload.get('status_counts', {})
        if not isinstance(status_counts, dict):
            status_counts = {}

        self.total_line_count = max(0, int(summary_payload.get('total_lines', 0) or 0))
        for status_code, field_name in self.ANALYSIS_STATUS_FIELD_MAP.items():
            setattr(self, field_name, max(0, int(status_counts.get(status_code, 0) or 0)))

    ANALYZED_LOG_TYPES = {'FRST', 'Addition', 'FRST&Addition'}

    def recalculate_analysis_stats(self):
        from .rule_sets import SHARED_RULE_SET_KEY, resolve_effective_rule_set_key

        effective_key = resolve_effective_rule_set_key(self)
        shared_payload = None
        effective_payload = None
        if self.log_type in self.ANALYZED_LOG_TYPES:
            from .analyzer import analyze_log_text, _detect_incomplete_log_warning
            content = self.content or ''
            shared_payload = analyze_log_text(content, SHARED_RULE_SET_KEY)
            if effective_key == SHARED_RULE_SET_KEY:
                effective_payload = shared_payload
            else:
                effective_payload = analyze_log_text(content, effective_key)
            self.apply_analysis_summary(effective_payload.get('summary', {}))
            self.is_incomplete = _detect_incomplete_log_warning(content) is not None
            for field_name in self.FIXLOG_STAT_FIELDS:
                setattr(self, field_name, 0)
        else:
            content = self.content or ''
            self.total_line_count = len([l for l in content.splitlines() if l.strip()])
            for field_name in self.ANALYSIS_STATUS_FIELD_MAP.values():
                setattr(self, field_name, 0)
            self.is_incomplete = False
            if self.log_type == 'Fixlog':
                self._compute_fixlog_stats(content)
            else:
                for field_name in self.FIXLOG_STAT_FIELDS:
                    setattr(self, field_name, 0)
        self.save(update_fields=[*self.analysis_stat_update_fields(), 'is_incomplete'])

        if shared_payload is not None:
            UploadedLogAnalysis.objects.update_or_create(
                upload=self,
                rule_set_key=SHARED_RULE_SET_KEY,
                defaults={'payload': shared_payload, 'source_content_hash': self.content_hash},
            )
        if effective_payload is not None and effective_key != SHARED_RULE_SET_KEY:
            UploadedLogAnalysis.objects.update_or_create(
                upload=self,
                rule_set_key=effective_key,
                defaults={'payload': effective_payload, 'source_content_hash': self.content_hash},
            )
        if shared_payload is None and effective_payload is None:
            UploadedLogAnalysis.objects.filter(upload=self).delete()

        update_uploaded_log_stat_snapshot(self, shared_payload)

    def _compute_fixlog_stats(self, content):
        total = 0
        success = 0
        not_found = 0
        error = 0
        for line in content.splitlines():
            idx = line.find(' => ')
            if idx == -1:
                continue
            total += 1
            status = line[idx + 4:]
            if 'successfully' in status:
                success += 1
            elif 'not found' in status:
                not_found += 1
            elif 'Error' in status:
                error += 1
        self.fixlog_total = total
        self.fixlog_success = success
        self.fixlog_not_found = not_found
        self.fixlog_error = error

    def recalculate_log_type(self):
        self.log_type = detect_log_type(self.content or '')
        self.save(update_fields=['log_type', 'updated_at'])

    def recalculate_scan_date(self):
        self.scan_date = extract_scan_date(self.content or '')
        self.save(update_fields=['scan_date', 'updated_at'])

    @classmethod
    def _generate_unique_upload_id(cls):
        # Prefer exactly two-word IDs. Only append a suffix if a collision occurs.
        for _ in range(25):
            candidate = generate_memorable_upload_id()
            if not cls.objects.filter(upload_id=candidate).exists():
                return candidate

        for _ in range(200):
            base = generate_memorable_upload_id()
            suffix = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(2))
            candidate = f'{base}-{suffix}'
            if not cls.objects.filter(upload_id=candidate).exists():
                return candidate

        raise ValidationError('Unable to generate a unique upload id.')


class UploadedLogAnalysis(models.Model):
    upload = models.ForeignKey(
        UploadedLog, on_delete=models.CASCADE, related_name='cached_analyses'
    )
    rule_set_key = models.CharField(max_length=64, db_index=True, default='shared')
    payload = models.JSONField()
    source_content_hash = models.CharField(max_length=32)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['upload', 'rule_set_key'],
                name='uploaded_log_analysis_unique_per_key',
            ),
        ]

    def __str__(self):
        return f'cached analysis for {self.upload_id} [{self.rule_set_key}]'


class FixlistSnippet(models.Model):
    DEFAULT_CATEGORY = 'generic'

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fixlist_snippets')
    name = models.CharField(max_length=255)
    content = models.TextField()
    category = models.CharField(max_length=255, default=DEFAULT_CATEGORY)
    is_shared = models.BooleanField(default=False)
    analyzer_users = models.ManyToManyField(User, related_name='analyzer_snippets', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        unique_together = ('owner', 'name')

    def __str__(self):
        return f"{self.name} ({self.owner.username})"


class InfectionCase(models.Model):
    STATUS_OPEN = 'open'
    STATUS_CLOSED = 'closed'
    STATUS_CHOICES = [
        (STATUS_OPEN, 'Open'),
        (STATUS_CLOSED, 'Closed'),
    ]

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='infection_cases')
    case_id = models.CharField(max_length=24, unique=True, db_index=True, blank=True)
    username = models.CharField(max_length=255, db_index=True)
    symptom_description = models.TextField(blank=True)
    reference_url = models.URLField(blank=True)
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=STATUS_OPEN)
    auto_assign_new_items = models.BooleanField(default=True)
    is_training = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True, default=None)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner', '-created_at']),
            models.Index(fields=['username', '-created_at']),
            models.Index(fields=['deleted_at']),
        ]

    def __str__(self):
        return f"{self.case_id} ({self.username})"

    def clean(self):
        self.username = (self.username or '').strip()
        if not self.username:
            raise ValidationError({'username': 'Username is required.'})

    def save(self, *args, **kwargs):
        self.clean()
        if self.is_training:
            self.auto_assign_new_items = False
        if not self.case_id:
            self.case_id = self._generate_unique_case_id()
        super().save(*args, **kwargs)

    @classmethod
    def _generate_unique_case_id(cls):
        for _ in range(40):
            candidate = generate_infection_case_id()
            if not cls.objects.filter(case_id=candidate).exists():
                return candidate
        raise ValidationError('Unable to generate a unique infection case id.')


class InfectionCaseLog(models.Model):
    case = models.ForeignKey(InfectionCase, on_delete=models.CASCADE, related_name='log_links')
    uploaded_log = models.ForeignKey(UploadedLog, on_delete=models.CASCADE, related_name='infection_case_links')
    added_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='added_case_logs')
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['added_at']
        constraints = [
            models.UniqueConstraint(fields=['case', 'uploaded_log'], name='unique_case_uploaded_log'),
        ]

    def __str__(self):
        return f"{self.case.case_id}:{self.uploaded_log.upload_id}"


class InfectionCaseFixlist(models.Model):
    case = models.ForeignKey(InfectionCase, on_delete=models.CASCADE, related_name='fixlist_links')
    fixlist = models.ForeignKey(Fixlist, on_delete=models.CASCADE, related_name='infection_case_links')
    added_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='added_case_fixlists')
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['added_at']
        constraints = [
            models.UniqueConstraint(fields=['case', 'fixlist'], name='unique_case_fixlist'),
        ]

    def __str__(self):
        return f"{self.case.case_id}:{self.fixlist_id}"


class InfectionCaseNote(models.Model):
    case = models.ForeignKey(InfectionCase, on_delete=models.CASCADE, related_name='note_entries')
    anchor_log = models.ForeignKey('InfectionCaseLog', null=True, blank=True, on_delete=models.SET_NULL, related_name='pinned_notes')
    anchor_note = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='pinned_notes')
    content = models.TextField()
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='infection_case_notes')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True, default=None)

    class Meta:
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['case', 'created_at']),
            models.Index(fields=['deleted_at']),
        ]

    def clean(self):
        self.content = (self.content or '').strip()
        if not self.content:
            raise ValidationError({'content': 'Note cannot be empty.'})

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.case.case_id}:note:{self.pk}"


class ParsedFilepathExclusion(models.Model):
    normalized_filepath = models.TextField(unique=True)
    note = models.TextField(blank=True)
    is_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['normalized_filepath']

    def clean(self):
        path = (self.normalized_filepath or '').strip()
        if not path:
            raise ValidationError({'normalized_filepath': 'Path cannot be empty.'})

        from . import frst_extractors as ex

        self.normalized_filepath = ex.normalize_path(path).lower().strip()

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.normalized_filepath


class UploadedLogStat(models.Model):
    source_id = models.PositiveIntegerField(unique=True, db_index=True)
    owner_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    owner_username = models.CharField(max_length=150, blank=True, default='', db_index=True)
    recipient_username = models.CharField(max_length=150, blank=True, default='')
    log_type = models.CharField(max_length=16, choices=UploadedLog.LOG_TYPE_CHOICES, default='Unknown', db_index=True)
    created_at = models.DateTimeField(db_index=True)
    total_line_count = models.PositiveIntegerField(default=0)
    count_malware = models.PositiveIntegerField(default=0)
    count_pup = models.PositiveIntegerField(default=0)
    count_clean = models.PositiveIntegerField(default=0)
    count_alert = models.PositiveIntegerField(default=0)
    count_warning = models.PositiveIntegerField(default=0)
    count_grayware = models.PositiveIntegerField(default=0)
    count_security = models.PositiveIntegerField(default=0)
    count_info = models.PositiveIntegerField(default=0)
    count_junk = models.PositiveIntegerField(default=0)
    count_unknown = models.PositiveIntegerField(default=0)
    fixlog_total = models.PositiveIntegerField(default=0)
    fixlog_success = models.PositiveIntegerField(default=0)
    fixlog_not_found = models.PositiveIntegerField(default=0)
    fixlog_error = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'UploadedLogStat(source_id={self.source_id})'


class FixlistStat(models.Model):
    source_id = models.PositiveIntegerField(unique=True, db_index=True)
    owner_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    owner_username = models.CharField(max_length=150, blank=True, default='', db_index=True)
    created_at = models.DateTimeField(db_index=True)
    line_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'FixlistStat(source_id={self.source_id})'


def _uploaded_log_stat_metadata(instance):
    """Snapshot fields that don't depend on which ruleset analyzed the log."""
    return {
        'owner_id': instance.created_by_id,
        'owner_username': instance.created_by.username if instance.created_by_id else '',
        'recipient_username': instance.recipient_user.username if instance.recipient_user_id else '',
        'log_type': instance.log_type,
        'created_at': instance.created_at,
        # Fixlog stats are computed from log text, not from any ruleset.
        **{f: getattr(instance, f) for f in UploadedLog.FIXLOG_STAT_FIELDS},
    }


def update_uploaded_log_stat_snapshot(instance, shared_payload):
    """Populate the historical stats snapshot from the SHARED analysis payload.

    Called explicitly from `UploadedLog.recalculate_analysis_stats` after the
    shared pass runs. The /stats/ view always reads this snapshot, so it must
    reflect the global ruleset regardless of which user owns the upload.
    """
    if instance.pk is None or instance.created_at is None:
        return
    defaults = _uploaded_log_stat_metadata(instance)
    summary = (shared_payload or {}).get('summary') if isinstance(shared_payload, dict) else None
    status_counts = (summary or {}).get('status_counts', {}) if isinstance(summary, dict) else {}
    if not isinstance(status_counts, dict):
        status_counts = {}
    defaults['total_line_count'] = max(0, int((summary or {}).get('total_lines', 0) or 0)) if summary else instance.total_line_count
    for status_code, field_name in UploadedLog.ANALYSIS_STATUS_FIELD_MAP.items():
        if summary is None:
            # Non-analyzable log types (Fixlog, Unknown) — count_* fields stay zero.
            defaults[field_name] = 0
        else:
            defaults[field_name] = max(0, int(status_counts.get(status_code, 0) or 0))
    UploadedLogStat.objects.update_or_create(source_id=instance.pk, defaults=defaults)


def _fixlist_stat_defaults(instance):
    return {
        'owner_id': instance.owner_id,
        'owner_username': instance.owner.username if instance.owner_id else '',
        'created_at': instance.created_at,
        'line_count': instance.line_count,
    }


@receiver(post_save, sender=UploadedLog)
def _snapshot_uploaded_log_stats(sender, instance, raw=False, **kwargs):
    """Keep the per-upload stats snapshot's metadata in sync on every save.

    Count fields (count_*, total_line_count) are NOT written here — they reflect
    the SHARED ruleset and are populated explicitly by `recalculate_analysis_stats`
    via `update_uploaded_log_stat_snapshot`. Writing them from `instance` here
    would leak the EFFECTIVE-ruleset values into /stats/.
    """
    if raw or instance.created_at is None:
        return
    existing = UploadedLogStat.objects.filter(source_id=instance.pk).first()
    metadata = _uploaded_log_stat_metadata(instance)
    if existing is None:
        # First save: create the row with zeroed counts; recalc will fill them in.
        defaults = dict(metadata)
        defaults['total_line_count'] = 0
        for field_name in UploadedLog.ANALYSIS_STATUS_FIELD_MAP.values():
            defaults[field_name] = 0
        UploadedLogStat.objects.create(source_id=instance.pk, **defaults)
    else:
        for field_name, value in metadata.items():
            setattr(existing, field_name, value)
        existing.save(update_fields=list(metadata.keys()))


@receiver(post_save, sender='fixlist.Fixlist')
def _snapshot_fixlist_stats(sender, instance, raw=False, **kwargs):
    if raw or instance.created_at is None:
        return
    FixlistStat.objects.update_or_create(
        source_id=instance.pk,
        defaults=_fixlist_stat_defaults(instance),
    )


@receiver(pre_delete, sender=User)
def _drop_rule_set_caches_on_user_delete(sender, instance, **kwargs):
    """A deleted user's rules cascade away; flush per-key caches so analyses recompute.

    Their `private:<id>` cached analyses become orphaned (no rules left in that
    key); shared callers also need a refresh because the user's contribution to
    the shared bucket is gone.
    """
    from .analyzer import invalidate_rule_buckets_cache
    invalidate_rule_buckets_cache(None)
    UploadedLogAnalysis.objects.filter(rule_set_key=f'private:{instance.id}').delete()


@receiver(post_save, sender=UploadedLog)
def _auto_assign_new_uploaded_log_to_infection_cases(sender, instance, created, raw=False, **kwargs):
    if raw or not created:
        return
    if instance.deleted_at is not None:
        return

    candidate_cases = InfectionCase.objects.filter(
        username=instance.forum_username,
        auto_assign_new_items=True,
        is_training=False,
        status=InfectionCase.STATUS_OPEN,
        deleted_at__isnull=True,
    )

    if instance.recipient_user_id is None:
        candidate_owner_ids = list(candidate_cases.values_list('owner_id', flat=True).distinct())
        if len(candidate_owner_ids) == 1:
            assigned_owner_id = candidate_owner_ids[0]
            sender.objects.filter(pk=instance.pk, recipient_user__isnull=True).update(
                recipient_user_id=assigned_owner_id,
                updated_at=timezone.now(),
            )
            instance.recipient_user_id = assigned_owner_id
            assigned_user = User.objects.filter(pk=assigned_owner_id).first()
            UploadedLogStat.objects.filter(source_id=instance.pk).update(
                recipient_username=assigned_user.username if assigned_user else '',
            )
        else:
            return

    if instance.recipient_user_id is not None:
        candidate_cases = candidate_cases.filter(owner_id=instance.recipient_user_id)

    InfectionCaseLog.objects.bulk_create(
        [
            InfectionCaseLog(case=case, uploaded_log=instance)
            for case in candidate_cases.only('id')
        ],
        ignore_conflicts=True,
    )


@receiver(post_save, sender=Fixlist)
def _auto_assign_new_fixlist_to_infection_cases(sender, instance, created, raw=False, **kwargs):
    if raw or not created:
        return
    if instance.deleted_at is not None:
        return

    candidate_cases = InfectionCase.objects.filter(
        owner=instance.owner,
        username=instance.username,
        auto_assign_new_items=True,
        is_training=False,
        status=InfectionCase.STATUS_OPEN,
        deleted_at__isnull=True,
    )

    InfectionCaseFixlist.objects.bulk_create(
        [
            InfectionCaseFixlist(case=case, fixlist=instance, added_by=instance.owner)
            for case in candidate_cases.only('id')
        ],
        ignore_conflicts=True,
    )
