from django.db import IntegrityError, models, transaction
from django.db.models import Q
from django.db.models.functions import Lower
from django.db.models.signals import post_delete, post_save, pre_delete, pre_save
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.dispatch import receiver
from datetime import timedelta
import hashlib
import logging
import secrets
import string
import re
import time

import mmh3
from django.utils import timezone

from .machine_signals import RAN_BY_WORDS
from .log_types import (
    DEFAULT_RULE_LOG_TYPES, default_rule_log_types, is_analyzed_log_type, rule_applies_to, scope_label, scope_payload,
)
from .status_types import STATUS_CHOICES as _STATUS_CHOICES, STATUS_CSS_CLASS

logger = logging.getLogger(__name__)

PRIORITY_MIN = 0
PRIORITY_MAX = 20
DEFAULT_PRIORITY_BY_MATCH_TYPE = {
    'exact': 19,
    'parsed': 15,
    'filepath': 11,
    'substring': 7,
    'script': 3,
    'regex': 3,
}
PRIORITY_DEFAULT_LABELS = {
    DEFAULT_PRIORITY_BY_MATCH_TYPE['exact']: 'exact line',
    DEFAULT_PRIORITY_BY_MATCH_TYPE['parsed']: 'parsed entries',
    DEFAULT_PRIORITY_BY_MATCH_TYPE['filepath']: 'filepath',
    DEFAULT_PRIORITY_BY_MATCH_TYPE['substring']: 'substring',
    # script and regex share the same default priority.
    DEFAULT_PRIORITY_BY_MATCH_TYPE['regex']: 'regex / script',
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


class SoftDeleteQuerySet(models.QuerySet):
    """Querysets of the models with a `deleted_at` trash timestamp."""

    def live(self):
        """Rows not in the trash."""
        return self.filter(deleted_at__isnull=True)

    def trashed(self):
        """Rows in the trash."""
        return self.filter(deleted_at__isnull=False)

    def move_to_trash(self, when=None) -> int:
        """Move every row to the trash (one UPDATE); returns how many."""
        from django.utils import timezone
        return self.update(deleted_at=when or timezone.now())


class Fixlist(models.Model):
    objects = SoftDeleteQuerySet.as_manager()

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fixlists')
    source_uploaded_log = models.ForeignKey('UploadedLog', on_delete=models.SET_NULL, null=True, blank=True, related_name='fixlists')
    username = models.CharField(max_length=255)
    content = models.TextField()
    internal_note = models.TextField(blank=True)
    # The reply written back to the infected user. Never rendered on the share
    # page, in the download or the copy API, so the user themselves never sees it.
    # Helpers do: it shows on the case timeline, which any authenticated helper
    # holding the case link can read.
    response = models.TextField(blank=True, default='')
    # When the response was first written, so it can be placed on a case timeline
    # by its own age rather than borrowing the fixlist's. Stamped on the save that
    # turns an empty response into a non-empty one, cleared when it is emptied.
    response_created_at = models.DateTimeField(null=True, blank=True, default=None)
    download_count = models.PositiveIntegerField(default=0)
    share_token = models.CharField(max_length=32, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_public = models.BooleanField(default=True)
    deleted_at = models.DateTimeField(null=True, blank=True, default=None)
    is_protected = models.BooleanField(
        default=False,
        help_text='Protected fixlists cannot be trashed, permanently deleted, or auto-purged.',
    )
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

    def set_response(self, text):
        """Assign the response text, keeping `response_created_at` in step.

        The stamp is set on the save that first gives the fixlist a response and
        cleared when the response is emptied, so re-writing a response later gets
        a fresh creation time instead of inheriting the old one. Returns the field
        names it touched, for callers passing `update_fields`.
        """
        text = (text or '').strip()
        self.response = text
        if not text:
            self.response_created_at = None
        elif self.response_created_at is None:
            self.response_created_at = timezone.now()
            # Read by the auto-assign receiver below: only a freshly written
            # response is auto-linked into cases, so a response someone unlinked
            # on purpose does not come back on the next edit.
            self._response_created_now = True
        return ['response', 'response_created_at']


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
    # Uploads / trash lists open on "all channels" instead of "my channel".
    uploads_all_channels_default = models.BooleanField(default=False)

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
    api_enabled = models.BooleanField(
        default=False,
        help_text='Kill switch for the read-only token API (/api/v1/) used by LLM clients. Off: every API request gets 503.',
    )
    centralbox_enabled = models.BooleanField(
        default=True,
        help_text=(
            'Kill switch for centralbox hash lookups. Off: no request is sent to centralbox; '
            'verdicts already stored are still shown with their date. Lookups also need the '
            'CENTRALBOX_API_KEY environment variable.'
        ),
    )
    # Set by centralbox.py when centralbox fails (down, key revoked, rate
    # limited): no calls until then, from any worker. Clear it to retry at once.
    centralbox_paused_until = models.DateTimeField(null=True, blank=True)
    centralbox_pause_reason = models.CharField(max_length=200, blank=True, default='')
    centralbox_auto_fresh_enabled = models.BooleanField(
        default=True,
        help_text=(
            'Automatic fresh centralbox lookups for likely malicious hashes (scanner detections, '
            'MAU removals, files of FRST lines at B / ! / P). Off: they are only started by hand; '
            'the queue is kept.'
        ),
    )
    # Lease of the one thread that works through CentralboxAutoQueue (see
    # centralbox_auto.py), shared by every worker. Clear it to let a new one start.
    centralbox_auto_drainer_until = models.DateTimeField(null=True, blank=True)
    # Bumped whenever the analyzer's in-memory rule buckets are invalidated, so
    # every worker process (not just the one that saved the rule) reloads them.
    # See analyzer.invalidate_rule_buckets_cache.
    rules_version = models.PositiveBigIntegerField(default=0, editable=False)
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
    def update_solo(cls, **fields):
        """UPDATE the single row in place (F() expressions allowed), creating it first if missing."""
        if not cls.objects.filter(pk=1).update(**fields):
            cls.objects.get_or_create(pk=1)
            cls.objects.filter(pk=1).update(**fields)

    @classmethod
    def current_guest_token(cls):
        return (cls.get_solo().guest_token or '').strip()

    @staticmethod
    def generate_guest_token():
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(32))

    @classmethod
    def api_is_enabled(cls):
        return bool(cls.get_solo().api_enabled)


class ApiToken(models.Model):
    """Personal bearer token for the read-only /api/v1/ endpoints.

    Only the sha256 of the raw token is stored; the raw value is shown to its
    owner once, at creation. A token acts as its user: it sees what that user
    sees in the browser and nothing more.
    """

    RAW_PREFIX = 'fh_'
    MAX_ACTIVE_PER_USER = 5
    EXPIRY_DAY_CHOICES = (30, 90, 180, 365)
    DEFAULT_EXPIRY_DAYS = 90

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_tokens')
    name = models.CharField(max_length=64)
    prefix = models.CharField(max_length=16)
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_used_at = models.DateTimeField(null=True, blank=True, default=None)
    revoked_at = models.DateTimeField(null=True, blank=True, default=None)
    revoked_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='revoked_api_tokens',
    )
    # Lets the token create and change rule tags, speeches, snippets and rules. Only superusers
    # can issue one, and every write re-checks that the user still is one.
    can_write = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.prefix}… ({self.user.username}: {self.name})'

    @staticmethod
    def hash_raw(raw: str) -> str:
        return hashlib.sha256((raw or '').encode('utf-8')).hexdigest()

    @property
    def is_active(self):
        return self.revoked_at is None and self.expires_at > timezone.now()

    @classmethod
    def active_for(cls, user):
        return cls.objects.filter(user=user, revoked_at__isnull=True, expires_at__gt=timezone.now())

    @classmethod
    def issue(cls, user, name, expiry_days=DEFAULT_EXPIRY_DAYS, can_write=False):
        """Create a token for `user` and return ``(token, raw)``.

        Raises ValidationError when the user already holds the maximum number of
        active tokens, the expiry is not one of EXPIRY_DAY_CHOICES, or a write
        token is asked for by someone who is not a superuser.
        """
        if expiry_days not in cls.EXPIRY_DAY_CHOICES:
            raise ValidationError('Unsupported token expiry.')
        if can_write and not user.is_superuser:
            raise ValidationError('Only superusers can create write tokens.')
        if cls.active_for(user).count() >= cls.MAX_ACTIVE_PER_USER:
            raise ValidationError(
                f'You already have {cls.MAX_ACTIVE_PER_USER} active tokens. Revoke one first.'
            )
        name = (name or '').strip()[:64] or 'token'
        raw = cls.RAW_PREFIX + secrets.token_urlsafe(30)
        token = cls.objects.create(
            user=user,
            name=name,
            prefix=raw[:8],
            token_hash=cls.hash_raw(raw),
            expires_at=timezone.now() + timedelta(days=expiry_days),
            can_write=bool(can_write),
        )
        return token, raw

    @classmethod
    def authenticate(cls, raw):
        """Return the active token for `raw` whose user is active, else None."""
        if not raw or not raw.startswith(cls.RAW_PREFIX):
            return None
        token = (
            cls.objects.select_related('user', 'user__fenris_profile')
            .filter(token_hash=cls.hash_raw(raw))
            .first()
        )
        if token is None or not token.is_active or not token.user.is_active:
            return None
        return token

    def revoke(self, by=None):
        """Revoke this token. Idempotent: a revoked token keeps its first revocation."""
        if self.revoked_at is not None:
            return False
        self.revoked_at = timezone.now()
        self.revoked_by = by
        self.save(update_fields=['revoked_at', 'revoked_by'])
        return True


class ApiRequestLog(models.Model):
    """One row per /api/v1/ request, the source of truth for usage stats and caps.

    Failed authentication is aggregated: one row per client IP per minute with
    `count` holding the number of attempts, so unauthenticated traffic cannot
    grow the table one row per request.
    """

    token = models.ForeignKey(ApiToken, null=True, blank=True, on_delete=models.SET_NULL, related_name='requests')
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='api_requests')
    endpoint = models.CharField(max_length=64)
    target = models.CharField(max_length=200, blank=True, default='')
    status_code = models.PositiveSmallIntegerField()
    response_bytes = models.PositiveIntegerField(default=0)
    duration_ms = models.PositiveIntegerField(default=0)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=200, blank=True, default='')
    count = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['token', 'created_at']),
        ]

    def __str__(self):
        return f'{self.endpoint} {self.status_code} at {self.created_at}'


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


class ClassificationRuleQuerySet(models.QuerySet):
    def reparseable(self):
        """Rules whose stored entry fields come from parsing their source text."""
        return self.filter(match_type__in=(
            ClassificationRule.MATCH_PARSED_ENTRY, ClassificationRule.MATCH_FILEPATH,
        ))


class RuleMatcherBase(models.Model):
    """What a rule matches log lines with: the match type and pattern, the log
    type scope and the fields parsed from the pattern. Classification rules
    (which set a line's status) and fact rules (which record a fact) both
    match this way, through the same analyzer matchers."""

    MATCH_EXACT = 'exact'
    MATCH_SUBSTRING = 'substring'
    MATCH_REGEX = 'regex'
    MATCH_FILEPATH = 'filepath'
    MATCH_PARSED_ENTRY = 'parsed'
    MATCH_SCRIPT = 'script'

    MATCH_TYPE_CHOICES = [
        (MATCH_EXACT, 'Exact line'),
        (MATCH_SUBSTRING, 'Substring'),
        (MATCH_REGEX, 'Regex'),
        (MATCH_FILEPATH, 'File path'),
        (MATCH_PARSED_ENTRY, 'Parsed'),
        (MATCH_SCRIPT, 'Python script'),
    ]

    match_type = models.CharField(max_length=16, choices=MATCH_TYPE_CHOICES)
    source_text = models.TextField(help_text='Rule input without description metadata.')
    description = models.TextField(blank=True)
    source_name = models.CharField(max_length=128, blank=True)
    is_enabled = models.BooleanField(default=True)
    # Log type scope: every log type (including ones added later), or only the
    # types named in `log_types` (exact names; ignored when all_log_types is set).
    all_log_types = models.BooleanField(
        default=False,
        help_text='Apply to every log type, including types added later.',
    )
    log_types = models.JSONField(
        default=default_rule_log_types,
        blank=True,
        help_text='Log type names this rule applies to (when not applying to all log types).',
    )
    # Advanced: the rule matches only lines FRST parses as one of these entry
    # types (frst_extractors.ENTRY_TYPES; any of a line's parsed entries
    # counts). Empty: any line. Ignored by whole-log rules.
    only_entry_types = models.JSONField(
        default=list,
        blank=True,
        help_text='Per-line rules only: match only lines parsed as one of these entry types (empty: any line).',
    )

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

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def applies_to_log_type(self, log_type) -> bool:
        return rule_applies_to(self.all_log_types, self.log_types, log_type)

    @property
    def log_scope_payload(self):
        """`"all"` or the list of log type names (API / JS form)."""
        return scope_payload(self.all_log_types, self.log_types)

    @property
    def log_scope_label(self) -> str:
        return scope_label(self.all_log_types, self.log_types)

    @property
    def has_default_log_scope(self) -> bool:
        """Applies to exactly the FRST types, as every rule did before scopes existed."""
        return not self.all_log_types and sorted(self.log_types or []) == sorted(DEFAULT_RULE_LOG_TYPES)


class ClassificationRule(RuleMatcherBase):
    objects = ClassificationRuleQuerySet.as_manager()

    is_fact_rule = False

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

    # Match types that colour only the text they matched unless `color_whole_line`
    # is set; every other match type always colours the whole analyzer line.
    COLOR_WHOLE_LINE_MATCH_TYPES = frozenset({
        RuleMatcherBase.MATCH_SUBSTRING, RuleMatcherBase.MATCH_FILEPATH, RuleMatcherBase.MATCH_REGEX,
    })

    status = models.CharField(max_length=1, choices=STATUS_CHOICES)
    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='classification_rules',
        default=get_default_rule_owner_id,
    )
    whole_log = models.BooleanField(
        default=False,
        help_text='Alert rules only: evaluate once against the whole log instead of per line.',
    )
    color_whole_line = models.BooleanField(
        default=False,
        help_text='Substring, file path and regex rules only: colour the whole analyzer line instead of just the matched text.',
    )
    tags = models.ManyToManyField('RuleTag', blank=True, related_name='rules')
    # What the rule tests: one line, or a whole block (log_layout: a Spor item
    # and its indented lines, an FRST Search file entry, an Addition event;
    # any other line is a block of its own). A block rule tests the block's
    # lines joined by line breaks and its verdict goes to every line of the
    # block, at the rule's priority. Spor parsed rules are always block rules.
    MATCH_UNIT_LINE = 'line'
    MATCH_UNIT_BLOCK = 'block'
    MATCH_UNIT_CHOICES = [(MATCH_UNIT_LINE, 'line'), (MATCH_UNIT_BLOCK, 'block')]
    match_unit = models.CharField(
        max_length=8,
        choices=MATCH_UNIT_CHOICES,
        default=MATCH_UNIT_LINE,
        help_text='Per-line rules only: test one line, or the whole block (its verdict goes to every line of the block).',
    )

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
    # The rule's conditions on facts (RuleCondition) in a fixed text form, ''
    # for a rule without any. Part of the rule's identity, so two rules may
    # differ in their conditions alone (OR: one rule per alternative). Written
    # only by fact_service.set_rule_conditions.
    condition_key = models.CharField(max_length=200, blank=True, default='', editable=False)

    class Meta:
        ordering = ['-priority', 'status', 'match_type', 'source_text']
        unique_together = ('owner', 'status', 'match_type', 'source_text', 'whole_log', 'condition_key', 'match_unit')
        constraints = [
            models.CheckConstraint(
                check=Q(priority__gte=PRIORITY_MIN) & Q(priority__lte=PRIORITY_MAX),
                name='classificationrule_priority_range',
            ),
        ]

    @property
    def status_css_class(self):
        return self.STATUS_CSS_CLASS_MAP.get(self.status, 'status-unknown')

    @property
    def shows_whole_line_badge(self) -> bool:
        """The rule opted into whole-line colour where it could colour just its match."""
        return (
            self.color_whole_line
            and self.match_type in self.COLOR_WHOLE_LINE_MATCH_TYPES
            and self.match_unit == self.MATCH_UNIT_LINE
        )

    @property
    def is_block_rule(self) -> bool:
        return self.match_unit == self.MATCH_UNIT_BLOCK

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


# A '#rrggbb' colour, as tag categories and log type badges store it.
HEX_COLOR_RE = re.compile(r'^#[0-9A-Fa-f]{6}$')
DEFAULT_COLOR = '#cccccc'
TAG_CATEGORY_COLOR_RE = HEX_COLOR_RE
DEFAULT_TAG_CATEGORY_COLOR = DEFAULT_COLOR
# The default category starts with the colour tag badges had before
# categories existed (--la-info).
DEFAULT_TAG_CATEGORY_NAME = 'default'
DEFAULT_TAG_CATEGORY_SEED_COLOR = '#8eb6d8'


class TagCategory(models.Model):
    """A group of rule tags sharing a colour: every tag badge of the category
    takes it (text and border), everywhere tags are shown. Shared, and anyone
    can edit them, like tags.

    Every tag has a category. Exactly one is the default (`is_default`): new
    tags get it, the tags of a deleted category move to it, and it cannot be
    deleted itself.

    `priority` (0-10) orders the tags on the uploads list and case log rows,
    highest first; priority 0 hides them there (for tags found in nearly
    every log).
    """

    NAME_MAX_LENGTH = 64
    PRIORITY_MIN = 0
    PRIORITY_MAX = 10
    DEFAULT_PRIORITY = 5

    name = models.CharField(max_length=NAME_MAX_LENGTH)
    color = models.CharField(max_length=7, default=DEFAULT_TAG_CATEGORY_COLOR)
    priority = models.PositiveSmallIntegerField(
        default=DEFAULT_PRIORITY,
        validators=[MinValueValidator(PRIORITY_MIN), MaxValueValidator(PRIORITY_MAX)],
    )
    is_default = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='created_tag_categories',
    )
    updated_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='updated_tag_categories',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        constraints = [
            models.UniqueConstraint(Lower('name'), name='unique_tag_category_name_ci'),
            models.UniqueConstraint(
                fields=['is_default'], condition=Q(is_default=True), name='single_default_tag_category',
            ),
        ]

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        if not TAG_CATEGORY_COLOR_RE.match(self.color or ''):
            raise ValidationError({'color': 'Color must be a 6-digit hex like #aabbcc.'})

    @classmethod
    def get_default(cls):
        """The default category, created if it is missing (it is seeded by migration 0083)."""
        category = cls.objects.filter(is_default=True).first()
        if category is None:
            category, _created = cls.objects.get_or_create(
                name__iexact=DEFAULT_TAG_CATEGORY_NAME,
                defaults={'name': DEFAULT_TAG_CATEGORY_NAME, 'color': DEFAULT_TAG_CATEGORY_SEED_COLOR},
            )
            category.is_default = True
            category.save(update_fields=['is_default'])
        return category


def default_tag_category_id():
    """Field default of RuleTag.category: a new tag starts in the default category.

    Reads only the id: migration 0083 calls this with the current model, before
    later migrations add TagCategory's newer columns, so loading whole rows here
    breaks migrating a fresh database.
    """
    pk = TagCategory.objects.filter(is_default=True).values_list('pk', flat=True).first()
    return pk if pk is not None else TagCategory.get_default().pk


class RuleTag(models.Model):
    """A shared label attached to rules: a malware family, a source, a vendor -
    any group of rules, whatever their status.

    Dozens of rules usually cover one family, and their descriptions name it
    in as many spellings, so speeches are suggested per tag rather than per
    rule. `match_pattern` is a regex (called "regex" in the UI) run
    case-insensitively against a rule's whole description: it drives the bulk
    apply preview on the tags page and the suggestions on the rule forms. Only
    with `auto_apply` does it tag new rules by itself - see tagging.auto_tag_rules.
    Tags are shared and anyone can edit them; `description` is for analysts.

    A built-in tag (`builtin_code` set) stands for one of the analyzer's
    hardcoded log warnings: it is "found" in a log when that warning fires, so
    speeches can be suggested for it. Otherwise it is an ordinary tag - it can
    sit on rules (say, extra alert rules for the same problem) and have a
    regex - but it cannot be deleted.
    """

    NAME_MAX_LENGTH = 64

    SCOPE_DESCRIPTION = 'description'
    SCOPE_SOURCE = 'source'
    SCOPE_ANY = 'any'
    SCOPE_CHOICES = [
        (SCOPE_DESCRIPTION, 'description'),
        (SCOPE_SOURCE, 'source line'),
        (SCOPE_ANY, 'anywhere'),
    ]

    name = models.CharField(max_length=NAME_MAX_LENGTH)
    description = models.TextField(blank=True)
    # The conditions a rule must meet to match the tag; all set ones must hold
    # (see tagging.TagConditions). A tag with none of regex, statuses or entry
    # types matches nothing and is applied by hand only.
    match_pattern = models.TextField(blank=True)
    exclude_pattern = models.TextField(blank=True)
    match_scope = models.CharField(max_length=16, choices=SCOPE_CHOICES, default=SCOPE_ANY)
    match_statuses = models.JSONField(default=list, blank=True)
    match_entry_types = models.JSONField(default=list, blank=True)
    auto_apply = models.BooleanField(default=False)
    # The same conditions also run on every analysed log line: the regex on the
    # line text, statuses on the line's verdict, entry types on its parsed
    # entry. A matching line carries the tag even when no tagged rule decided
    # it. Results are stored per cached analysis (UploadedLogAnalysis.line_tags).
    match_log_lines = models.BooleanField(default=False)
    # The regex also runs on the centralbox family and malware type of the
    # SHA256s in scanner logs and Fixlogs (HashVerdict): such a log carries the
    # tag, and its log page shows it next to the hash (tagging.centralbox_tag_hits).
    match_centralbox = models.BooleanField(default=False)
    builtin_code = models.CharField(max_length=64, null=True, blank=True, unique=True, default=None)
    # Sets the badge colour. Deleting a category moves its tags to the default
    # one first (views.tags.tag_categories_view), so PROTECT never fires there.
    category = models.ForeignKey(
        TagCategory, on_delete=models.PROTECT, default=default_tag_category_id, related_name='tags',
    )
    created_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='created_rule_tags',
    )
    updated_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='updated_rule_tags',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        constraints = [
            models.UniqueConstraint(Lower('name'), name='unique_rule_tag_name_ci'),
        ]

    def __str__(self):
        return self.name


class Fact(models.Model):
    """A named observation about a log, e.g. "Kaspersky installed".

    A fact is found in a log by its fact rules (FactRule: their own patterns)
    or its tag sources (FactTagSource: classification rules with a tag that
    matched). Conditional rules require or forbid facts. Facts are not tags:
    tags group rules, facts describe logs. Shared, and anyone can edit them,
    like tags; fact rules are owned like classification rules.
    """

    NAME_MAX_LENGTH = 64

    name = models.CharField(max_length=NAME_MAX_LENGTH)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='created_facts',
    )
    updated_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='updated_facts',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        constraints = [
            models.UniqueConstraint(Lower('name'), name='unique_fact_name_ci'),
        ]

    def __str__(self):
        return self.name


class FactRule(RuleMatcherBase):
    """A pattern that records its fact wherever it matches, instead of setting
    a status. Never takes part in a line's verdict, shadowing or colouring,
    and has no conditions of its own (so facts cannot depend on facts).

    A whole-log fact rule (regex or script) is tested once against the whole
    log: its fact is about the log and has no line.
    """

    objects = ClassificationRuleQuerySet.as_manager()

    # Listed with classification rules on the rules page, which tells them apart by this.
    is_fact_rule = True

    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='fact_rules',
        default=get_default_rule_owner_id,
    )
    fact = models.ForeignKey(Fact, on_delete=models.CASCADE, related_name='fact_rules')
    whole_log = models.BooleanField(
        default=False,
        help_text='Regex and script only: evaluate once against the whole log; the fact has no line.',
    )

    class Meta:
        ordering = ['match_type', 'source_text']
        unique_together = ('owner', 'fact', 'match_type', 'source_text', 'whole_log')

    def __str__(self):
        owner_name = self.owner.username if self.owner_id else 'unknown'
        return f"fact {self.fact_id} [{self.match_type}] {self.source_text[:80]} ({owner_name})"


class FactTagSource(models.Model):
    """A fact found wherever a classification rule carrying `tag` matched.

    `statuses` limits it to rules with these statuses (empty: any), so a tag
    that also holds rules for fakes (B) can feed "installed" only through its
    S/C rules. In `decided` mode the rule must have decided the line; in
    `matched` mode a match shadowed by a stronger rule counts too. Matches
    through a parsed rule's file path alone count only with
    `include_filepath_fallback`. Whole-log alert rules with the tag that fired
    count as a fact about the log. Conditional rules never count.
    """

    MODE_DECIDED = 'decided'
    MODE_MATCHED = 'matched'
    MODE_CHOICES = [
        (MODE_MATCHED, 'matched (shadowed matches count too)'),
        (MODE_DECIDED, 'decided the line'),
    ]

    fact = models.ForeignKey(Fact, on_delete=models.CASCADE, related_name='tag_sources')
    tag = models.ForeignKey('RuleTag', on_delete=models.PROTECT, related_name='fact_sources')
    statuses = models.JSONField(default=list, blank=True)
    mode = models.CharField(max_length=16, choices=MODE_CHOICES, default=MODE_MATCHED)
    include_filepath_fallback = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['fact', 'tag']
        unique_together = ('fact', 'tag')

    def __str__(self):
        return f"{self.fact_id} <- tag {self.tag_id}"


class RuleCondition(models.Model):
    """A classification rule applies only where its conditions hold: each
    requires or forbids a fact in the line's block, section or anywhere in
    the log. All of a rule's conditions must hold.

    Facts are found before any conditional rule is evaluated, and conditional
    rules never find facts, so conditions cannot depend on each other.
    """

    POLARITY_REQUIRE = 'require'
    POLARITY_FORBID = 'forbid'
    POLARITY_CHOICES = [(POLARITY_REQUIRE, 'require'), (POLARITY_FORBID, 'forbid')]

    SCOPE_BLOCK = 'block'
    SCOPE_SECTION = 'section'
    SCOPE_LOG = 'log'
    SCOPE_CHOICES = [
        (SCOPE_BLOCK, 'in the same block'),
        (SCOPE_SECTION, 'in the same section'),
        (SCOPE_LOG, 'anywhere in the log'),
    ]

    MAX_PER_RULE = 8

    rule = models.ForeignKey(ClassificationRule, on_delete=models.CASCADE, related_name='conditions')
    fact = models.ForeignKey(Fact, on_delete=models.PROTECT, related_name='conditions')
    polarity = models.CharField(max_length=8, choices=POLARITY_CHOICES, default=POLARITY_REQUIRE)
    scope = models.CharField(max_length=8, choices=SCOPE_CHOICES, default=SCOPE_LOG)

    class Meta:
        ordering = ['rule', 'fact']
        unique_together = ('rule', 'fact')

    def __str__(self):
        return f"rule {self.rule_id}: {self.polarity} fact {self.fact_id} in {self.scope}"


from .log_types import (  # noqa: E402 - re-exported, many modules import these from models
    ANALYZED_LOG_TYPES, DEFAULT_RULE_LOG_TYPES, LOG_TYPE_ADDITION, LOG_TYPE_FRST, LOG_TYPE_FRST_AND_ADDITION,
    LOG_TYPE_NAME_RE, LOG_TYPE_UNKNOWN,
)

_HEADER_WINDOW_CHARS = 4096
_PATTERN_CACHE = {'version': None, 'rules': []}


def _current_logtype_rules_version():
    """A signature of the active rule set: (enabled_count, max_updated_at_iso)."""
    from django.db.models import Count, Max
    try:
        agg = LogTypeDetectionRule.objects.filter(is_enabled=True).aggregate(
            n=Count('id'), m=Max('updated_at'),
        )
    except Exception:
        return None
    return (agg['n'] or 0, agg['m'].isoformat() if agg['m'] else '')


def _bump_logtype_rules_version():
    """No-op kept for backwards compatibility — version is derived live from DB."""
    _PATTERN_CACHE['version'] = None


def _load_compiled_logtype_rules():
    """Return [(rule, compiled_pattern), ...] sorted by priority. Cached per rule-set signature."""
    version = _current_logtype_rules_version()
    if version is None:
        return []
    if _PATTERN_CACHE['version'] == version:
        return _PATTERN_CACHE['rules']
    compiled = []
    try:
        qs = LogTypeDetectionRule.objects.filter(is_enabled=True).order_by('priority', 'id')
    except Exception:
        return []
    for rule in qs:
        try:
            compiled.append((rule, re.compile(rule.pattern)))
        except re.error:
            continue
    _PATTERN_CACHE['version'] = version
    _PATTERN_CACHE['rules'] = compiled
    return compiled


_FIXLIST_CONTENT_RE = re.compile(r'^fixlist content:\s*$', re.I)
_FIXLIST_STARS_RE = re.compile(r'^\*{5,}\s*$')


def count_fixlog_results(content: str) -> dict:
    """Count the ` => ` result lines of a Fixlog.

    A Fixlog first echoes the fixlist it ran ("fixlist content:" followed by
    the fixlist between two '*****' lines). Those echoed lines often contain
    ` => ` too (FRST entries such as "FirewallRules: [...] => (Block) ...") but
    are not results, so they are skipped. Pure function: also used by the
    migration that recounts stored Fixlogs.
    """
    counts = {'total': 0, 'success': 0, 'not_found': 0, 'error': 0}
    for _line_no, _target, status in iter_fixlog_results(content):
        counts['total'] += 1
        if 'successfully' in status:
            counts['success'] += 1
        elif 'not found' in status:
            counts['not_found'] += 1
        elif 'Error' in status:
            counts['error'] += 1
    return counts


def iter_fixlog_results(content: str):
    """Yield ``(line_no, target, result)`` for each ` => ` result line of a Fixlog.

    `line_no` counts ``content.split('\\n')`` from 1, like the log page's line
    anchors; `target` is the text before ` => `, `result` the text after it.
    Each such line is split again with ``splitlines()`` (as
    log_highlighting.apply_analysis_statuses does), so lines are the same as
    ``content.splitlines()`` and the counts match what migration 0092 stored,
    even with lone '\\r' or other line separators. The echoed fixlist
    ("fixlist content:" up to the second '*****' line) is skipped, see
    count_fixlog_results. Pure function.
    """
    in_fixlist = False
    stars = 0
    for index, raw in enumerate((content or '').split('\n')):
        for line in raw.splitlines():
            if in_fixlist:
                if _FIXLIST_STARS_RE.match(line):
                    stars += 1
                    if stars >= 2:
                        in_fixlist = False
                continue
            if _FIXLIST_CONTENT_RE.match(line):
                in_fixlist = True
                stars = 0
                continue
            idx = line.find(' => ')
            if idx == -1:
                continue
            yield index + 1, line[:idx], line[idx + 4:]


def detect_log_type(content: str) -> str:
    if not content:
        return LOG_TYPE_UNKNOWN
    compiled = _load_compiled_logtype_rules()
    if not compiled:
        return LOG_TYPE_UNKNOWN
    head = content.lstrip()[:_HEADER_WINDOW_CHARS]
    matched_types = set()
    first_match_type = None
    for rule, pat in compiled:
        target = head if rule.scope == LogTypeDetectionRule.SCOPE_START else content
        if pat.search(target):
            matched_types.add(rule.log_type)
            if first_match_type is None:
                first_match_type = rule.log_type
    if LOG_TYPE_FRST in matched_types and LOG_TYPE_ADDITION in matched_types:
        return LOG_TYPE_FRST_AND_ADDITION
    if first_match_type:
        return first_match_type
    return LOG_TYPE_UNKNOWN


# "Ran by" in every language FRST writes, shared with machine_signals.
_SCAN_DATE_RE = re.compile(
    r'(?:' + '|'.join(re.escape(word) for word in RAN_BY_WORDS) + r') '
    r'[^\r\n]{0,400}?\((\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})\)'
)


def extract_scan_date(content: str):
    """Extract the scan datetime from a FRST/Addition/Fixlog header.

    Returns a timezone-aware datetime (in the project's current timezone)
    or None. The FRST timestamp itself carries no tz info, so we treat it
    as wall-clock in TIME_ZONE.
    """
    from datetime import datetime as dt
    from django.utils import timezone
    m = _SCAN_DATE_RE.search(content)
    if m:
        try:
            naive = dt.strptime(m.group(1), '%d-%m-%Y %H:%M:%S')
        except ValueError:
            return None
        return timezone.make_aware(naive, timezone.get_current_timezone())
    return None


LOG_TYPE_COLOR_RE = HEX_COLOR_RE
DEFAULT_LOG_TYPE_COLOR = DEFAULT_COLOR
RESERVED_LOG_TYPE_NAMES = {'unknown'}


def log_type_css_slug(name: str) -> str:
    """Map a log_type name to its CSS class slug. Keeps backward compatibility
    with the existing convention used in templates (lowercased, '&' and spaces
    stripped) while dropping any other character that isn't safe inside a CSS
    class selector — notably '.', which the browser would parse as a class
    boundary (e.g. 'Dr.Web' -> 'log-type-dr.web' would match two classes)."""
    lowered = (name or '').lower().replace('&', '').replace(' ', '')
    return re.sub(r'[^a-z0-9_-]', '', lowered)


class LogTypeBadge(models.Model):
    """User-defined visual label + color for a log_type. One row per distinct log_type name.
    Existence of a row is not required for detection — it only governs the badge color."""

    name = models.CharField(max_length=32, unique=True)
    color = models.CharField(max_length=7, default=DEFAULT_LOG_TYPE_COLOR)
    is_builtin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.color})"

    @property
    def css_slug(self) -> str:
        return log_type_css_slug(self.name)

    def clean(self):
        super().clean()
        if not self.name or not LOG_TYPE_NAME_RE.match(self.name):
            raise ValidationError({'name': 'Name must start with a letter or digit and contain only letters, digits, spaces, &, ., _ or - (max 32 chars).'})
        if self.name.lower() in RESERVED_LOG_TYPE_NAMES:
            raise ValidationError({'name': f'"{self.name}" is reserved.'})
        if not LOG_TYPE_COLOR_RE.match(self.color or ''):
            raise ValidationError({'color': 'Color must be a 6-digit hex like #aabbcc.'})


class LogTypeDetectionRule(models.Model):
    SCOPE_FULL = 'full'
    SCOPE_START = 'start'
    SCOPE_CHOICES = [
        (SCOPE_FULL, 'Anywhere in content'),
        (SCOPE_START, 'Header (first 4KB)'),
    ]

    name = models.CharField(max_length=120)
    log_type = models.CharField(max_length=32)
    pattern = models.TextField()
    scope = models.CharField(max_length=8, choices=SCOPE_CHOICES, default=SCOPE_START)
    is_enabled = models.BooleanField(default=True, db_index=True)
    is_builtin = models.BooleanField(default=False)
    priority = models.IntegerField(default=100)
    notes = models.TextField(blank=True, default='')
    created_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='created_log_type_rules',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['priority', 'id']
        indexes = [models.Index(fields=['is_enabled', 'priority'])]

    def __str__(self):
        return f"{self.name} → {self.log_type} (p{self.priority})"

    def clean(self):
        super().clean()
        if not self.log_type or not LOG_TYPE_NAME_RE.match(self.log_type):
            raise ValidationError({'log_type': 'Invalid log_type name.'})
        if self.log_type.lower() in RESERVED_LOG_TYPE_NAMES:
            raise ValidationError({'log_type': f'"{self.log_type}" is reserved.'})
        if not self.pattern or not self.pattern.strip():
            raise ValidationError({'pattern': 'Pattern is required.'})
        try:
            re.compile(self.pattern)
        except re.error as exc:
            raise ValidationError({'pattern': f'Invalid regex: {exc}'})


def known_log_type_names() -> list:
    """Every log type a rule can be scoped to: the FRST types first, then the
    badge and detection-rule names alphabetically ('Unknown' left out)."""
    names = set(LogTypeBadge.objects.values_list('name', flat=True))
    names.update(LogTypeDetectionRule.objects.values_list('log_type', flat=True))
    names.difference_update(DEFAULT_RULE_LOG_TYPES)
    names.discard(LOG_TYPE_UNKNOWN)
    return list(DEFAULT_RULE_LOG_TYPES) + sorted(names, key=str.lower)


@receiver(post_save, sender=LogTypeDetectionRule)
def _logtype_rule_saved(sender, instance, **kwargs):
    _bump_logtype_rules_version()


@receiver(pre_delete, sender=LogTypeDetectionRule)
def _logtype_rule_deleted(sender, instance, **kwargs):
    _bump_logtype_rules_version()


class AnalysisCountsBase(models.Model):
    """Per-status line counts and Fixlog result counts of an uploaded log; shared
    by the log itself and its statistics snapshot (UploadedLogStat)."""

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
        abstract = True

    @staticmethod
    def counts_from_summary(summary) -> dict:
        """``{field: value}`` for total_line_count and the count_* fields from an
        analysis summary (``{'total_lines': n, 'status_counts': {code: n}}``)."""
        summary = summary if isinstance(summary, dict) else {}
        status_counts = summary.get('status_counts', {})
        if not isinstance(status_counts, dict):
            status_counts = {}
        counts = {'total_line_count': max(0, int(summary.get('total_lines', 0) or 0))}
        for status_code, field_name in UploadedLog.ANALYSIS_STATUS_FIELD_MAP.items():
            counts[field_name] = max(0, int(status_counts.get(status_code, 0) or 0))
        return counts


class UploadedLog(AnalysisCountsBase):
    objects = SoftDeleteQuerySet.as_manager()

    # Kept as a hint for code that wants the canonical built-in names; not enforced.
    KNOWN_LOG_TYPES = (
        'FRST', 'Addition', 'FRST&Addition', 'Fixlog', 'Shortcut',
        'ESET', 'AdwCleaner', 'HitmanPro', 'Emsisoft', 'Malwarebytes', 'Unknown',
    )

    upload_id = models.CharField(max_length=64, unique=True, db_index=True)
    forum_username = models.CharField(max_length=100, db_index=True)
    original_filename = models.CharField(max_length=255)
    log_type = models.CharField(max_length=32, default='Unknown')
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
    is_protected = models.BooleanField(
        default=False,
        help_text='Protected logs cannot be trashed, permanently deleted, merged away, or auto-purged.',
    )
    FIXLOG_STAT_FIELDS = ['fixlog_total', 'fixlog_success', 'fixlog_not_found', 'fixlog_error']
    # Small precomputed [[label, value, severity], ...] chips for tool logs
    # (ESET, MAU, SecurityCheck, ...) shown in the uploads / cases lists.
    tool_stats = models.JSONField(default=list, blank=True)
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
        from .rule_sets import resolve_effective_rule_set_key, rule_set_label
        return rule_set_label(resolve_effective_rule_set_key(self))

    @classmethod
    def analysis_stat_fields(cls):
        return ['total_line_count', *cls.ANALYSIS_STATUS_FIELD_MAP.values(), *cls.FIXLOG_STAT_FIELDS]

    @classmethod
    def analysis_stat_update_fields(cls):
        return [*cls.analysis_stat_fields(), 'updated_at']

    def apply_analysis_summary(self, summary: dict):
        for field_name, value in self.counts_from_summary(summary).items():
            setattr(self, field_name, value)

    ANALYZED_LOG_TYPES = ANALYZED_LOG_TYPES

    def recalculate_analysis_stats(self):
        from .rule_sets import SHARED_RULE_SET_KEY, resolve_effective_rule_set_key

        effective_key = resolve_effective_rule_set_key(self)
        shared_payload = None
        effective_payload = None
        if is_analyzed_log_type(self.log_type):
            from .analyzer import analyze_log_text, _detect_incomplete_log_warning
            content = self.content or ''
            # Analysis is linear in line count and is the single most expensive
            # thing this app does. Recording size and duration together makes a
            # creeping regression visible in the logs before it starts timing
            # out requests -- and identifies the log when one does.
            started = time.monotonic()
            shared_payload = analyze_log_text(content, SHARED_RULE_SET_KEY, self.log_type)
            if effective_key == SHARED_RULE_SET_KEY:
                effective_payload = shared_payload
            else:
                effective_payload = analyze_log_text(content, effective_key, self.log_type)
            logger.info(
                'analysed upload_id=%s type=%s lines=%s rule_set=%s in %.1fs',
                self.upload_id,
                self.log_type,
                shared_payload.get('summary', {}).get('total_lines', 0),
                effective_key,
                time.monotonic() - started,
            )
            self.apply_analysis_summary(effective_payload.get('summary', {}))
            # FRST types only: the check returns None for every other type.
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
        from .log_highlighting import compute_tool_stats
        self.tool_stats = compute_tool_stats(self.log_type, self.content or '')
        self.save(update_fields=[*self.analysis_stat_update_fields(), 'is_incomplete', 'tool_stats'])
        # SHA256s for the centralbox markers; local parsing only, never raises.
        UploadedLogFileHash.rebuild_for(self)
        # Machine fingerprint for the same-system checks; never raises.
        UploadedLogMachineSignal.rebuild_for(self)

        from .tagging import compute_line_tags, current_line_tags
        from .upload_utils import store_cached_analysis

        line_tags = current_line_tags()
        shared_line_tags = compute_line_tags(shared_payload, line_tags) if shared_payload is not None else None
        if shared_payload is not None:
            store_cached_analysis(self, SHARED_RULE_SET_KEY, shared_payload, line_tags=shared_line_tags)
        if effective_payload is not None and effective_key != SHARED_RULE_SET_KEY:
            store_cached_analysis(
                self, effective_key, effective_payload,
                line_tags=compute_line_tags(effective_payload, line_tags),
            )
        if shared_payload is None and effective_payload is None:
            UploadedLogAnalysis.objects.filter(upload=self).delete()

        update_uploaded_log_stat_snapshot(self, shared_payload, shared_line_tags)

    def _compute_fixlog_stats(self, content):
        counts = count_fixlog_results(content)
        self.fixlog_total = counts['total']
        self.fixlog_success = counts['success']
        self.fixlog_not_found = counts['not_found']
        self.fixlog_error = counts['error']

    def recalculate_log_type(self) -> bool:
        """Re-run detection; saves and returns True only when the type changed."""
        new_type = detect_log_type(self.content or '')
        if new_type == self.log_type:
            return False
        self.log_type = new_type
        self.save(update_fields=['log_type', 'updated_at'])
        return True

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
    # Which log lines the line-matching tags matched, so listings, tag search
    # and stats read stored ids instead of running regexes per page view:
    # {"sigs": {tag_id: conditions signature}, "lines": {tag_id: [line index]}}.
    # A tag whose signature differs or is missing is recomputed on read (see
    # tagging.fresh_line_tags); None means never computed.
    line_tags = models.JSONField(null=True, blank=True, default=None)
    # What listings and tag search need from `payload`, so they never decode
    # it: {"format": payload format, "rule_ids": [...], "codes": [warning code]}.
    # Derived from `payload` on every save (see tagging.tag_summary_of); None
    # only for rows written around save(), which readers then derive on read.
    tag_summary = models.JSONField(null=True, blank=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['upload', 'rule_set_key'],
                name='uploaded_log_analysis_unique_per_key',
            ),
        ]

    def save(self, *args, **kwargs):
        from .tagging import tag_summary_of

        self.tag_summary = tag_summary_of(self.payload)
        update_fields = kwargs.get('update_fields')
        if update_fields is not None and 'payload' in update_fields and 'tag_summary' not in update_fields:
            kwargs['update_fields'] = [*update_fields, 'tag_summary']
        super().save(*args, **kwargs)

    def __str__(self):
        return f'cached analysis for {self.upload_id} [{self.rule_set_key}]'


class UploadedLogFileHash(models.Model):
    """A SHA256 found in an uploaded log, with the file it belongs to (see
    file_hashes.extract_file_hashes). Rebuilt with the analysis stats.

    `auto` rows (scanner detections, MAU files, Fixlog File: blocks) are looked
    up on centralbox by themselves; the rest only when an analyst asks from the
    hash menu. `anchor_line_no` is the detection / path line the hash belongs
    to, which the summary box flags. `normalized_path` is the analyzer's
    filepath key, so a case's FRST lines can be matched against it.
    """

    upload = models.ForeignKey(UploadedLog, on_delete=models.CASCADE, related_name='file_hashes')
    # '' for an MD5-only row (Trojan Killer); see `md5`.
    sha256 = models.CharField(max_length=64, db_index=True, blank=True, default='')
    # The file's MD5 when the log gives one. A row with both is a local
    # MD5 -> SHA256 pair (centralbox.resolve_md5s), so a Trojan Killer MD5 can
    # show the verdict of a file seen in a Malwarebytes log or a Fixlog.
    md5 = models.CharField(max_length=32, db_index=True, blank=True, default='')
    line_no = models.PositiveIntegerField()
    anchor_line_no = models.PositiveIntegerField()
    path = models.TextField(blank=True, default='')
    normalized_path = models.TextField(blank=True, default='')
    detection = models.CharField(max_length=255, blank=True, default='')
    source = models.CharField(max_length=32, default='other')
    auto = models.BooleanField(default=False)

    class Meta:
        ordering = ['upload', 'line_no']
        indexes = [models.Index(fields=['upload', 'auto'], name='fixlist_filehash_upload_auto')]

    def __str__(self):
        return f'{self.sha256 or self.md5} in {self.upload_id} line {self.line_no}'

    @classmethod
    def rebuild_for(cls, upload):
        """Replace the upload's rows from its current content. Never raises:
        a parsing problem must not break the stats recalculation around it."""
        from .file_hashes import extract_file_hashes

        def build_rows():
            return [
                cls(
                    upload=upload, sha256=row.sha256, line_no=row.line_no,
                    anchor_line_no=row.anchor_line_no, path=row.path,
                    normalized_path=row.normalized_path, detection=row.detection,
                    source=row.source, auto=row.auto, md5=row.md5,
                )
                for row in extract_file_hashes(upload.log_type, upload.content or '')
            ]

        _replace_upload_rows(cls, upload, build_rows, 'file hashes')


def _replace_upload_rows(model, upload, build_rows, label):
    """Replace `upload`'s rows of `model` with `build_rows()`. Never raises: a
    parsing problem must not break the stats recalculation around it.

    One unit: readers never see the log without rows, a failed insert keeps
    the old ones, and the savepoint keeps an outer transaction usable after
    the error is swallowed.
    """
    try:
        rows = build_rows()
        with transaction.atomic():
            model.objects.filter(upload=upload).delete()
            model.objects.bulk_create(rows, batch_size=1000)
    except Exception:
        logger.exception('Storing %s failed for upload_id=%s', label, upload.upload_id)


class UploadedLogMachineSignal(models.Model):
    """One machine signal of an uploaded log (machine_signals.py: machine SID,
    computer name, profile, Disk ID, hardware, ...), stored as a sha1 of the
    value: only compared, never shown. Rebuilt with the analysis stats."""

    upload = models.ForeignKey(UploadedLog, on_delete=models.CASCADE, related_name='machine_signals')
    kind = models.CharField(max_length=16)
    value = models.CharField(max_length=40)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['upload', 'kind', 'value'], name='machine_signal_unique'),
        ]
        indexes = [models.Index(fields=['kind', 'value'], name='fixlist_machsig_kind_value')]

    def __str__(self):
        return f'{self.kind} of {self.upload_id}'

    @classmethod
    def rows_for(cls, upload_pk, content):
        from .machine_signals import log_signals

        return [
            cls(upload_id=upload_pk, kind=kind, value=value)
            for kind, values in log_signals(content).items() for value in sorted(values)
        ]

    @classmethod
    def rebuild_for(cls, upload):
        """Replace the upload's rows from its current content. Never raises."""
        _replace_upload_rows(cls, upload, lambda: cls.rows_for(upload.pk, upload.content or ''), 'machine signals')


class HashVerdict(models.Model):
    """centralbox's answer for one SHA256, cached and kept even when centralbox
    is down or gone (the page then shows it with its date). Only validated
    values are stored; see centralbox.py, the only code that writes it."""

    STATE_KNOWN = 'known'
    STATE_UNKNOWN = 'unknown'
    STATE_CHOICES = [(STATE_KNOWN, 'known'), (STATE_UNKNOWN, 'not in centralbox')]
    VERDICT_CLEAN = 'clean'
    VERDICT_SUSPICIOUS = 'suspicious'
    VERDICT_MALICIOUS = 'malicious'
    VERDICTS = (VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS)

    sha256 = models.CharField(max_length=64, unique=True)
    state = models.CharField(max_length=16, choices=STATE_CHOICES)
    verdict = models.CharField(max_length=16, blank=True, default='')
    family = models.CharField(max_length=64, blank=True, default='')
    malware_type = models.CharField(max_length=32, blank=True, default='')
    score = models.SmallIntegerField(null=True, blank=True)
    threat_score = models.SmallIntegerField(null=True, blank=True)
    # {"malicious": 5, "suspicious": 1, ...} from /verdict, only for flagged hashes.
    provider_counts = models.JSONField(default=dict, blank=True)
    # [{"source": "Triage", "status": "malicious", "url": "https://..."}], at most 6.
    links = models.JSONField(default=list, blank=True)
    checked_at = models.DateTimeField()
    next_check_at = models.DateTimeField(db_index=True)

    class Meta:
        ordering = ['-checked_at']

    def __str__(self):
        return f'{self.sha256} {self.verdict or self.state}'

    def as_dict(self):
        return {
            'sha256': self.sha256,
            'state': self.state,
            'verdict': self.verdict,
            'family': self.family,
            'malware_type': self.malware_type,
            'threat_score': self.threat_score,
            'checked_at': self.checked_at.date().isoformat() if self.checked_at else '',
            'report_url': f'https://centralbox.dev/analysis/{self.sha256}' if self.state == self.STATE_KNOWN else '',
            'links': list(self.links or [])[:6],
        }


class CorrelationCache(models.Model):
    """The correlations of an FRST log (case_correlations.correlations_for_upload),
    per viewer scope: 'case:<owner id>' when the viewer has a case with the log,
    else 'user' (the forum user's logs, the same for everyone). `signature`
    covers everything the result depends on; a mismatch means recompute."""

    upload = models.ForeignKey(UploadedLog, on_delete=models.CASCADE, related_name='correlation_caches')
    scope_key = models.CharField(max_length=40)
    signature = models.CharField(max_length=40)
    payload = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['upload', 'scope_key'], name='correlation_cache_unique_scope'),
        ]

    def __str__(self):
        return f'correlations of {self.upload_id} [{self.scope_key}]'


class HashAlias(models.Model):
    """centralbox's answer for an MD5: the SHA256 it stands for, or '' when
    centralbox did not know it at `checked_at`. Written by centralbox.py after
    a manual MD5 check or an MD5 fresh lookup; the verdict itself is the
    SHA256's HashVerdict. (Pairs seen in logs need no row here: they are in
    UploadedLogFileHash.)"""

    md5 = models.CharField(max_length=32, unique=True)
    sha256 = models.CharField(max_length=64, blank=True, default='', db_index=True)
    checked_at = models.DateTimeField()
    next_check_at = models.DateTimeField()

    class Meta:
        ordering = ['-checked_at']

    def __str__(self):
        return f'{self.md5} -> {self.sha256 or "not in centralbox"}'


class CentralboxUsageMinute(models.Model):
    """Calls to centralbox per wall-clock minute and API key, shared by every
    worker process (the cache is per process). centralbox.take_budget
    increments it atomically and refuses once the minute's limit is reached.
    `key_id` is the budget bucket of the server key: '' for reads, 'fresh'
    for fresh lookups."""

    minute = models.BigIntegerField()
    key_id = models.CharField(max_length=16, blank=True, default='')
    calls = models.PositiveIntegerField(default=0)
    failures = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-minute']
        constraints = [
            models.UniqueConstraint(fields=['minute', 'key_id'], name='centralbox_usage_minute_key_unique'),
        ]

    def __str__(self):
        return f'minute {self.minute} [{self.key_id or "server"}]: {self.calls} calls, {self.failures} failures'


class CentralboxFreshLookup(models.Model):
    """A fresh centralbox analysis a helper started for one SHA256 (with their
    own key). One row per hash: it enforces the cooldown for everyone and
    tracks the run while the page waits for it. The result itself goes to
    HashVerdict like every other answer."""

    STATE_RUNNING = 'running'
    STATE_DONE = 'done'
    STATE_NOT_FOUND = 'not_found'
    STATE_ERROR = 'error'
    STATE_CHOICES = [
        (STATE_RUNNING, 'running'), (STATE_DONE, 'done'),
        (STATE_NOT_FOUND, 'not found anywhere'), (STATE_ERROR, 'error'),
    ]

    # The looked-up hash: a SHA256, or an MD5 (Trojan Killer).
    sha256 = models.CharField(max_length=64, unique=True)
    requested_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='centralbox_fresh_lookups',
    )
    requested_at = models.DateTimeField()
    state = models.CharField(max_length=16, choices=STATE_CHOICES, default=STATE_RUNNING)
    finished_at = models.DateTimeField(null=True, blank=True)
    # Started by Fenris itself (centralbox_auto.py), not by a helper's click.
    auto = models.BooleanField(default=False)

    class Meta:
        ordering = ['-requested_at']

    def __str__(self):
        return f'{self.sha256} {self.state} ({self.requested_at:%Y-%m-%d %H:%M})'


class CentralboxAutoQueue(models.Model):
    """A likely malicious hash waiting for an automatic fresh centralbox
    lookup (centralbox_auto.py). One row per hash; deleted when its lookup
    starts, when it turns out not to need one, or when it gets too old."""

    PRIORITY_SCANNER = 0
    PRIORITY_FRST_B = 1
    PRIORITY_MAU = 2
    PRIORITY_FRST_FLAGGED = 3

    # A SHA256, or an MD5 (Trojan Killer, Fixlog folder listings).
    hash = models.CharField(max_length=64, unique=True)
    priority = models.PositiveSmallIntegerField(default=PRIORITY_FRST_FLAGGED)
    reason = models.CharField(max_length=200, blank=True, default='')
    enqueued_at = models.DateTimeField()

    class Meta:
        ordering = ['priority', 'enqueued_at']
        indexes = [models.Index(fields=['priority', 'enqueued_at'], name='fixlist_cbqueue_order')]

    def __str__(self):
        return f'{self.hash} (priority {self.priority}: {self.reason})'


class FixlistSnippet(models.Model):
    DEFAULT_CATEGORY = 'generic'

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fixlist_snippets')
    name = models.CharField(max_length=255)
    content = models.TextField()
    category = models.CharField(max_length=255, default=DEFAULT_CATEGORY)
    is_shared = models.BooleanField(default=False)
    analyzer_users = models.ManyToManyField(User, related_name='analyzer_snippets', blank=True)
    # The analyzer suggests the snippet when one of these tags is found in the
    # analysed log (built-in tags included, for the hardcoded warnings).
    trigger_tags = models.ManyToManyField(RuleTag, blank=True, related_name='snippets')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        unique_together = ('owner', 'name')

    def __str__(self):
        return f"{self.name} ({self.owner.username})"


class Speech(models.Model):
    """A reusable block of prose for the analyzer's response panel.

    Mirrors FixlistSnippet: snippets are canned fixlist lines, speeches are the
    canned paragraphs that go back to the user in the forum.
    """

    DEFAULT_CATEGORY = 'generic'

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='speeches')
    name = models.CharField(max_length=255)
    content = models.TextField()
    category = models.CharField(max_length=255, default=DEFAULT_CATEGORY)
    is_shared = models.BooleanField(default=False)
    analyzer_users = models.ManyToManyField(User, related_name='analyzer_speeches', blank=True)
    # The analyzer suggests the speech when one of these tags is found in the
    # analysed log (built-in tags included, for the hardcoded warnings).
    trigger_tags = models.ManyToManyField(RuleTag, blank=True, related_name='speeches')
    # The helper's FRST fix message: edited in the profile, copied from the
    # fixlist page, and listed here among the speeches. One per helper.
    is_fix_message = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        unique_together = ('owner', 'name')
        constraints = [
            models.UniqueConstraint(
                fields=['owner'], condition=Q(is_fix_message=True), name='one_fix_message_speech_per_owner',
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.owner.username})"


class InfectionCaseQuerySet(SoftDeleteQuerySet):
    def auto_assign_targets(self, username, owner=None):
        """Open, live, non-training cases of `username` (and `owner`) that collect new items."""
        qs = self.filter(
            InfectionCase.username_q(username),
            auto_assign_new_items=True,
            is_training=False,
            status=InfectionCase.STATUS_OPEN,
            deleted_at__isnull=True,
        )
        if owner is not None:
            qs = qs.filter(owner=owner)
        return qs.distinct()


class InfectionCase(models.Model):
    objects = InfectionCaseQuerySet.as_manager()

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
    # Reopening counts as activity for auto-close, otherwise a reopened stale case
    # would be closed again on the next load of the cases list.
    reopened_at = models.DateTimeField(null=True, blank=True, default=None)
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

    def set_status(self, new_status):
        """Apply a requested status. Returns False (and changes nothing) if it is invalid."""
        if new_status not in {self.STATUS_OPEN, self.STATUS_CLOSED}:
            return False
        if new_status == self.STATUS_OPEN and self.status == self.STATUS_CLOSED:
            self.reopened_at = timezone.now()
        self.status = new_status
        return True

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

    MAX_EXTRA_USERNAMES = 20

    def extra_username_list(self):
        """The case's other forum usernames, in the order they were entered."""
        if self.pk is None:
            return []
        return [row.username for row in self.extra_usernames.all()]

    def all_usernames(self):
        """The main username first, then the other ones."""
        return [self.username, *self.extra_username_list()]

    @classmethod
    def clean_extra_usernames(cls, names, main_username=''):
        """Stripped, deduplicated other usernames without the main one (exact
        comparison, as everywhere for case usernames); at most
        MAX_EXTRA_USERNAMES, 1-255 characters each."""
        if isinstance(names, str):
            names = names.split(',')
        result = []
        for name in names or []:
            name = (name or '').strip()[:255]
            if name and name != main_username and name not in result:
                result.append(name)
        return result[:cls.MAX_EXTRA_USERNAMES]

    def set_extra_usernames(self, names):
        """Replace the other usernames (see clean_extra_usernames). Returns the stored list."""
        cleaned = self.clean_extra_usernames(names, self.username)
        self.extra_usernames.exclude(username__in=cleaned).delete()
        existing = set(self.extra_usernames.values_list('username', flat=True))
        InfectionCaseUsername.objects.bulk_create(
            [InfectionCaseUsername(case=self, username=name) for name in cleaned if name not in existing],
            ignore_conflicts=True,
        )
        return cleaned

    @staticmethod
    def username_q(username, prefix=''):
        """Q for cases whose main or other username is exactly `username`
        (use with .distinct(): the other names are a join)."""
        return Q(**{f'{prefix}username': username}) | Q(**{f'{prefix}extra_usernames__username': username})


class InfectionCaseUsername(models.Model):
    """Another forum username of an infection case (the main one is
    InfectionCase.username). Matched exactly, like the main one: new logs,
    fixlists and responses of any of the case's names join it."""

    case = models.ForeignKey(InfectionCase, on_delete=models.CASCADE, related_name='extra_usernames')
    username = models.CharField(max_length=255, db_index=True)

    class Meta:
        ordering = ['id']
        constraints = [
            models.UniqueConstraint(fields=['case', 'username'], name='infection_case_username_unique'),
        ]

    def __str__(self):
        return f'{self.username} ({self.case_id})'


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


class InfectionCaseResponse(models.Model):
    """A response's membership in a case.

    The text lives on Fixlist.response, but inside a case the response is an item
    in its own right: linked, unlinked and annotated independently of the fixlist
    it belongs to.
    """

    case = models.ForeignKey(InfectionCase, on_delete=models.CASCADE, related_name='response_links')
    fixlist = models.ForeignKey(Fixlist, on_delete=models.CASCADE, related_name='infection_case_response_links')
    added_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='added_case_responses')
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['added_at']
        constraints = [
            models.UniqueConstraint(fields=['case', 'fixlist'], name='unique_case_response'),
        ]

    def __str__(self):
        return f"{self.case.case_id}:response:{self.fixlist_id}"


class InfectionCaseNote(models.Model):
    objects = SoftDeleteQuerySet.as_manager()

    case = models.ForeignKey(InfectionCase, on_delete=models.CASCADE, related_name='note_entries')
    anchor_log = models.ForeignKey('InfectionCaseLog', null=True, blank=True, on_delete=models.SET_NULL, related_name='pinned_notes')
    anchor_fixlist = models.ForeignKey('InfectionCaseFixlist', null=True, blank=True, on_delete=models.SET_NULL, related_name='pinned_notes')
    anchor_response = models.ForeignKey('InfectionCaseResponse', null=True, blank=True, on_delete=models.SET_NULL, related_name='pinned_notes')
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

        self.normalized_filepath = ex.path_key(path)

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.normalized_filepath


class UploadedLogStat(AnalysisCountsBase):
    source_id = models.PositiveIntegerField(unique=True, db_index=True)
    owner_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    owner_username = models.CharField(max_length=150, blank=True, default='', db_index=True)
    # The forum user who posted the log, as stat_username keys it; '' unknown
    # (the log was gone before snapshots recorded it).
    forum_username = models.CharField(max_length=100, blank=True, default='', db_index=True)
    recipient_username = models.CharField(max_length=150, blank=True, default='')
    log_type = models.CharField(max_length=32, default='Unknown', db_index=True)
    created_at = models.DateTimeField(db_index=True)
    # What the shared analysis credited - its rules and the codes of its
    # warnings - so /stats/ can count rule tags. Tags are resolved from these
    # when the page is served, like everywhere else, so tagging a rule later
    # counts for past logs too. None: never recorded (the snapshot predates
    # tag stats and its log was gone before they could be backfilled).
    rule_ids = models.JSONField(null=True, blank=True, default=None)
    warning_codes = models.JSONField(null=True, blank=True, default=None)
    # The tags matched on the shared analysis's log lines (RuleTag.match_log_lines).
    # Unlike rule tags these cannot be resolved later - the snapshot keeps no
    # lines - so they are stored, and refreshed for logs that still exist when
    # a line tag changes. None: never recorded.
    line_tag_ids = models.JSONField(null=True, blank=True, default=None)
    # The SHA256s of related scanner / Fixlog logs that correlate with the
    # log's lines (case_correlations), stored whenever the correlations are
    # computed. Their centralbox tags are resolved when /stats/ is served, like
    # rule tags. None: never correlated.
    correlated_sha256s = models.JSONField(null=True, blank=True, default=None)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'UploadedLogStat(source_id={self.source_id})'


class FixlistStat(models.Model):
    source_id = models.PositiveIntegerField(unique=True, db_index=True)
    owner_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    owner_username = models.CharField(max_length=150, blank=True, default='', db_index=True)
    # The forum user the fixlist is for, as stat_username keys it; '' unknown.
    username = models.CharField(max_length=255, blank=True, default='', db_index=True)
    created_at = models.DateTimeField(db_index=True)
    line_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'FixlistStat(source_id={self.source_id})'


def stat_username(value):
    """A forum username as the stats key it: stripped and lowercased, like the
    case-insensitive related-logs lookup. '' for none."""
    return (value or '').strip().lower()


def _uploaded_log_stat_metadata(instance):
    """Snapshot fields that don't depend on which ruleset analyzed the log."""
    return {
        'owner_id': instance.created_by_id,
        'owner_username': instance.created_by.username if instance.created_by_id else '',
        'forum_username': stat_username(instance.forum_username),
        'recipient_username': instance.recipient_user.username if instance.recipient_user_id else '',
        'log_type': instance.log_type,
        'created_at': instance.created_at,
        # Fixlog stats are computed from log text, not from any ruleset.
        **{f: getattr(instance, f) for f in UploadedLog.FIXLOG_STAT_FIELDS},
    }


def update_uploaded_log_stat_snapshot(instance, shared_payload, shared_line_tags=None):
    """Populate the historical stats snapshot from the SHARED analysis payload.

    Called explicitly from `UploadedLog.recalculate_analysis_stats` after the
    shared pass runs. The /stats/ view always reads this snapshot, so it must
    reflect the global ruleset regardless of which user owns the upload.
    `shared_line_tags` is the line tag matches stored with that analysis
    (computed here when not given).
    """
    if instance.pk is None or instance.created_at is None:
        return
    defaults = _uploaded_log_stat_metadata(instance)
    summary = (shared_payload or {}).get('summary') if isinstance(shared_payload, dict) else None
    # Non-analyzable log types (Fixlog, Unknown) have no summary: count_* stay zero.
    defaults.update(UploadedLog.counts_from_summary(summary))
    if not summary:
        defaults['total_line_count'] = instance.total_line_count
    defaults.update(stat_tag_fields(shared_payload, shared_line_tags))
    UploadedLogStat.objects.update_or_create(source_id=instance.pk, defaults=defaults)


# Every write of a snapshot's tag sources goes through the helpers below, so
# /stats/ reads what log search and the uploads list read from the cache.

def stat_tag_fields(payload, line_tags=None, summary=None):
    """The snapshot's tag sources - ``{rule_ids, warning_codes, line_tag_ids}`` - of a shared analysis.

    Rule ids and codes are the cache row's `tag_summary` (pass `summary` when
    it is at hand, else it is derived from `payload`); line tag ids are the
    stored `line_tags` matches (computed from `payload` when not given).
    Empty lists without a payload: logs the analyzer skips hold no tags.
    """
    from .tagging import compute_line_tags, line_tag_hits, tag_summary_of

    if summary is None:
        summary = tag_summary_of(payload)
    if summary is None:
        return {'rule_ids': [], 'warning_codes': [], 'line_tag_ids': []}
    if line_tags is None:
        line_tags = compute_line_tags(payload) if isinstance(payload, dict) else None
    return {
        'rule_ids': sorted(summary.get('rule_ids') or []),
        'warning_codes': sorted(summary.get('codes') or []),
        'line_tag_ids': sorted(line_tag_hits(line_tags)),
    }


def sync_stat_tag_sources(upload_pk, payload, line_tags=None):
    """Point a log's snapshot at a newly cached shared analysis; the count_* fields are left alone."""
    UploadedLogStat.objects.filter(source_id=upload_pk).update(**stat_tag_fields(payload, line_tags))


def sync_stat_line_tag_ids(upload_pk, line_tag_ids):
    """Store a log's refreshed line tag matches in its snapshot (see tagging.refresh_line_tags)."""
    UploadedLogStat.objects.filter(source_id=upload_pk).update(line_tag_ids=sorted(line_tag_ids))


def sync_stat_correlated_hashes(upload_pk, sha256s):
    """Store the SHA256s correlated with a log's lines (see case_correlations.correlated_sha256s)."""
    UploadedLogStat.objects.filter(source_id=upload_pk).update(correlated_sha256s=sorted(sha256s))


def _fixlist_stat_defaults(instance):
    return {
        'owner_id': instance.owner_id,
        'owner_username': instance.owner.username if instance.owner_id else '',
        'username': stat_username(instance.username),
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


@receiver(post_save, sender=User)
def _give_new_account_a_fix_message_speech(sender, instance, created, raw=False, **kwargs):
    """Every new helper starts with the default FRST fix message as a speech.

    Accounts nobody can log in to (rule_owner_fallback and other passwordless
    placeholders) never write a reply, so they get none. An empty password
    counts as "usable" to Django, hence the explicit check - rule_owner_fallback
    is created that way, inside a migration that runs before speeches exist.
    """
    if raw or not created or not instance.is_active:
        return
    if not instance.password or not instance.has_usable_password():
        return
    from .fix_message import ensure_fix_message_speech
    ensure_fix_message_speech(instance)


# The rule fields a tag's conditions look at (see tagging.TagConditions).
_TAG_CONDITION_FIELDS = ('description', 'source_text', 'status', 'entry_type')


@receiver(pre_save, sender=ClassificationRule)
def _note_rule_tag_fields_change(sender, instance, raw=False, **kwargs):
    """Remember whether this save changes what tag conditions look at.

    Auto tags are added only to new rules and to rules whose description,
    source line, status or entry type changes, so a tag removed from a rule by
    hand stays removed.
    """
    if raw:
        instance._tag_fields_changed = False
        return
    if instance.pk is None:
        instance._tag_fields_changed = True
        return
    previous = sender.objects.filter(pk=instance.pk).values_list(*_TAG_CONDITION_FIELDS).first()
    current = tuple(getattr(instance, field) for field in _TAG_CONDITION_FIELDS)
    instance._tag_fields_changed = previous != current


@receiver([post_save, post_delete], sender=ClassificationRule)
def _drop_tag_rule_match_cache(sender, raw=False, **kwargs):
    """A saved or deleted rule can change which rules a tag's conditions match.

    Other processes notice through the rules fingerprint; this drops this
    process's cache at once, even when the fingerprint would not move (a
    rolled-back test reusing primary keys within one clock tick).
    """
    if raw:
        return
    from .tagging import clear_rule_match_cache
    clear_rule_match_cache()


@receiver(post_save, sender=ClassificationRule)
def _auto_tag_saved_rule(sender, instance, raw=False, **kwargs):
    if raw or not getattr(instance, '_tag_fields_changed', False):
        return
    instance._tag_fields_changed = False
    from .tagging import auto_tag_rules
    auto_tag_rules([instance])


@receiver(post_save, sender=UploadedLog)
def _auto_assign_new_uploaded_log_to_infection_cases(sender, instance, created, raw=False, **kwargs):
    if raw or not created:
        return
    if instance.deleted_at is not None:
        return

    candidate_cases = InfectionCase.objects.auto_assign_targets(instance.forum_username)

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

    candidate_cases = InfectionCase.objects.auto_assign_targets(instance.username, owner=instance.owner)

    InfectionCaseFixlist.objects.bulk_create(
        [
            InfectionCaseFixlist(case=case, fixlist=instance, added_by=instance.owner)
            for case in candidate_cases.only('id')
        ],
        ignore_conflicts=True,
    )


@receiver(post_save, sender=Fixlist)
def _auto_assign_new_response_to_infection_cases(sender, instance, raw=False, **kwargs):
    """Link a newly written response into the same cases a new fixlist would join.

    Fires only on the save that first gives the fixlist a response (see
    `Fixlist.set_response`), never on later edits, so unlinking a response from a
    case is not silently undone the next time the text is touched.
    """
    if raw or not getattr(instance, '_response_created_now', False):
        return
    instance._response_created_now = False
    if instance.deleted_at is not None:
        return

    candidate_cases = InfectionCase.objects.auto_assign_targets(instance.username, owner=instance.owner)

    InfectionCaseResponse.objects.bulk_create(
        [
            InfectionCaseResponse(case=case, fixlist=instance, added_by=instance.owner)
            for case in candidate_cases.only('id')
        ],
        ignore_conflicts=True,
    )
