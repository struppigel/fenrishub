from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils.text import slugify
import secrets
import string


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
    title = models.CharField(max_length=255)
    content = models.TextField()
    internal_note = models.TextField(blank=True)
    download_count = models.PositiveIntegerField(default=0)
    share_token = models.CharField(max_length=32, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_public = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} by {self.owner.username}"

    def save(self, *args, **kwargs):
        if not self.share_token:
            self.share_token = self.generate_share_token()
        super().save(*args, **kwargs)

    @staticmethod
    def generate_share_token():
        """Generate a random secure share token."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(32))


class AccessLog(models.Model):
    fixlist = models.ForeignKey(Fixlist, on_delete=models.CASCADE, related_name='accesses')
    accessed_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        ordering = ['-accessed_at']

    def __str__(self):
        return f"Access to {self.fixlist.title} at {self.accessed_at}"


class ClassificationRule(models.Model):
    STATUS_MALWARE = 'B'
    STATUS_PUP = 'P'
    STATUS_CLEAN = 'C'
    STATUS_WARNING = '!'
    STATUS_GRAYWARE = 'G'
    STATUS_SECURITY = 'S'
    STATUS_INFO = 'I'
    STATUS_JUNK = 'J'
    STATUS_UNKNOWN = '?'

    STATUS_CHOICES = [
        (STATUS_MALWARE, 'Userdefined malware'),
        (STATUS_PUP, 'Userdefined potentially unwanted'),
        (STATUS_CLEAN, 'Userdefined clean entries'),
        (STATUS_WARNING, 'Userdefined warning'),
        (STATUS_GRAYWARE, 'Userdefined grayware'),
        (STATUS_SECURITY, 'Userdefined security software'),
        (STATUS_INFO, 'Userdefined informational'),
        (STATUS_JUNK, 'Userdefined junk'),
        (STATUS_UNKNOWN, 'Unknown'),
    ]

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
        (MATCH_PARSED_ENTRY, 'Parsed FRST entry'),
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

    def __str__(self):
        owner_name = self.owner.username if self.owner_id else 'unknown'
        return f"{self.status} [{self.match_type}] {self.source_text[:80]} ({owner_name})"


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
