from django.db import IntegrityError, models
from django.db.models.signals import post_save
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.dispatch import receiver
import secrets
import string
import re

import mmh3
from django.utils import timezone


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
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='fenris_profile')
    frst_fix_message = models.TextField(blank=True, default='')
    word_wrap = models.BooleanField(default=False)
    analyzer_fixlist_template = models.TextField(blank=True, default='')

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

    STATUS_CHOICES = [
        (STATUS_MALWARE, 'Malware'),
        (STATUS_PUP, 'Potentially unwanted'),
        (STATUS_CLEAN, 'Clean'),
        (STATUS_WARNING, 'Warning'),
        (STATUS_ALERT, 'Alert'),
        (STATUS_GRAYWARE, 'Grayware'),
        (STATUS_SECURITY, 'Security software'),
        (STATUS_INFO, 'Informational'),
        (STATUS_JUNK, 'Junk'),
        (STATUS_UNKNOWN, 'Unknown'),
    ]

    STATUS_CSS_CLASS_MAP = {
        'B': 'status-b', 'P': 'status-p', 'C': 'status-c',
        '!': 'status-w', 'A': 'status-a', 'G': 'status-g', 'S': 'status-s',
        'I': 'status-i', 'J': 'status-j', '?': 'status-unknown',
    }

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

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['status', 'match_type', 'source_text']
        unique_together = ('owner', 'status', 'match_type', 'source_text')

    @property
    def status_css_class(self):
        return self.STATUS_CSS_CLASS_MAP.get(self.status, 'status-unknown')

    def __str__(self):
        owner_name = self.owner.username if self.owner_id else 'unknown'
        return f"{self.status} [{self.match_type}] {self.source_text[:80]} ({owner_name})"


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
    reddit_username = models.CharField(max_length=20, db_index=True)
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
        return f'{self.upload_id} ({self.reddit_username})'

    def clean(self):
        username = (self.reddit_username or '').strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{3,20}', username):
            raise ValidationError({'reddit_username': 'Use 3-20 letters, numbers, underscores, or hyphens.'})
        if not (self.content or '').strip():
            raise ValidationError({'content': 'Uploaded content cannot be empty.'})
        self.reddit_username = username

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
        if self.log_type in self.ANALYZED_LOG_TYPES:
            from .analyzer import analyze_log_text, _detect_incomplete_log_warning
            content = self.content or ''
            analysis = analyze_log_text(content)
            self.apply_analysis_summary(analysis.get('summary', {}))
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


@receiver(post_save, sender=UploadedLog)
def _auto_assign_new_uploaded_log_to_infection_cases(sender, instance, created, raw=False, **kwargs):
    if raw or not created:
        return
    if instance.deleted_at is not None:
        return

    candidate_cases = InfectionCase.objects.filter(
        username=instance.reddit_username,
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
