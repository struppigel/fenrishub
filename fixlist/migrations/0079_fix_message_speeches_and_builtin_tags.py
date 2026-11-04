"""Give every helper their FRST fix message as a flagged speech, and seed the
built-in rule tags for the analyzer's hardcoded log warnings.

The fix message used to be a profile column. It now lives in one speech per
helper (`is_fix_message`), which the profile edits, the fixlist page's "copy
fix message" uses, and the speeches page lists. Each helper account gets one
holding the text they would have copied until now: their custom message, or
the default, unchanged. Accounts nobody logs in to (rule_owner_fallback and
other passwordless placeholders) get none. The profile column stays, so this
can be rolled back without losing anyone's text.

New accounts get theirs from a post_save receiver on User (models.py).
"""

from django.db import migrations

SPEECH_NAME = 'FRST fix'
SPEECH_CATEGORY = 'fix'

# Frozen copies; a migration must not import from code that keeps changing.
DEFAULT_FRST_FIX_MESSAGE = """**FRST Fix**

* Open the following link and press on the **Copy contents** button to copy the entire text: [fixlist for {USERNAME}]({FIXLISTLINK})
* Run **FRST64.exe** and click on **Fix**. Note: FRST reads the fixlist directly from your clipboard, so you don't need to paste or save it anywhere.
* A log (Fixlog.txt) will open on your desktop.
* Copy & paste the contents of the Fixlog.txt to [https://malwareanalysis.cc/upload/{HELPERNAME}/?u={USERNAME}](https://malwareanalysis.cc/upload/{HELPERNAME}/?u={USERNAME}) and press **\"save log\"**. Reply back with the keyword

I have included the EmptyTemp: command. Note: This will remove cookies and may result in some websites (like banking) indicating they do not recognize your computer. It may be necessary to receive and apply a verification code.

It is normal for your system to reboot as a result of the fix."""

BUILTIN_TAGS = [
    ('incomplete_logs', 'incomplete logs', 'The FRST or Addition log is cut off before its end marker.'),
    ('low_memory', 'low memory', 'Little RAM, high RAM usage or little free space on the Windows drive.'),
    ('multiple_enabled_av', 'multiple enabled AVs', 'More than one antivirus product is enabled.'),
    ('recent_restore_operation', 'recent system restore', 'A system restore was run recently.'),
    ('recent_os_install', 'recent Windows install', 'Windows was installed or feature-updated recently.'),
]


def _free_name(taken):
    name = SPEECH_NAME
    counter = 2
    while name in taken:
        name = f'{SPEECH_NAME} ({counter})'
        counter += 1
    return name


def create_fix_message_speeches(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    UserProfile = apps.get_model('fixlist', 'UserProfile')
    Speech = apps.get_model('fixlist', 'Speech')

    custom_messages = dict(UserProfile.objects.values_list('user_id', 'frst_fix_message'))
    has_one = set(Speech.objects.filter(is_fix_message=True).values_list('owner_id', flat=True))

    helpers = (
        User.objects.filter(is_active=True)
        .exclude(pk__in=has_one)
        .exclude(password='')
        .exclude(password__startswith='!')
    )
    for user in helpers:
        taken = set(Speech.objects.filter(owner=user).values_list('name', flat=True))
        speech = Speech.objects.create(
            owner=user,
            name=_free_name(taken),
            category=SPEECH_CATEGORY,
            content=(custom_messages.get(user.pk) or '').strip() or DEFAULT_FRST_FIX_MESSAGE,
            is_shared=False,
            is_fix_message=True,
        )
        speech.analyzer_users.add(user)


def seed_builtin_tags(apps, schema_editor):
    RuleTag = apps.get_model('fixlist', 'RuleTag')
    for code, name, description in BUILTIN_TAGS:
        if RuleTag.objects.filter(builtin_code=code).exists():
            continue
        # A user tag may already carry the name; the built-in one yields.
        unique_name = name
        while RuleTag.objects.filter(name__iexact=unique_name).exists():
            unique_name = f'{unique_name} (built-in)'
        RuleTag.objects.create(name=unique_name, description=description, builtin_code=code)


def forwards(apps, schema_editor):
    create_fix_message_speeches(apps, schema_editor)
    seed_builtin_tags(apps, schema_editor)


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0078_rule_tags_and_fix_message_speech'),
    ]

    operations = [
        migrations.RunPython(forwards, migrations.RunPython.noop),
    ]
