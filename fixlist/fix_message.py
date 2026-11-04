"""The helper's FRST fix message.

It is one speech flagged `is_fix_message`, shown in two places: edited in the
profile settings (as the fix message always was) and listed on the speeches
page, where it can also be picked into a response in the analyzer. The
fixlist page's "copy fix message" fills it with that fixlist's values.

Every account that can log in gets one with the default text on creation.
"""

from .models import Speech

DEFAULT_FRST_FIX_MESSAGE_TEMPLATE = """**FRST Fix**

* Open the following link and press on the **Copy contents** button to copy the entire text: [fixlist for {USERNAME}]({FIXLISTLINK})
* Run **FRST64.exe** and click on **Fix**. Note: FRST reads the fixlist directly from your clipboard, so you don't need to paste or save it anywhere.
* A log (Fixlog.txt) will open on your desktop.
* Copy & paste the contents of the Fixlog.txt to [https://malwareanalysis.cc/upload/{HELPERNAME}/?u={USERNAME}](https://malwareanalysis.cc/upload/{HELPERNAME}/?u={USERNAME}) and press **\"save log\"**. Reply back with the keyword

I have included the EmptyTemp: command. Note: This will remove cookies and may result in some websites (like banking) indicating they do not recognize your computer. It may be necessary to receive and apply a verification code.

It is normal for your system to reboot as a result of the fix."""

FIX_MESSAGE_SPEECH_NAME = 'FRST fix'
FIX_MESSAGE_SPEECH_CATEGORY = 'fix'


def fix_message_speech(user):
    """The user's flagged FRST fix speech, or None."""
    if not user or not user.is_authenticated:
        return None
    return Speech.objects.filter(owner=user, is_fix_message=True).first()


def effective_fix_message(user):
    """The fix message text to use for `user`: their speech, or the default."""
    speech = fix_message_speech(user)
    content = (speech.content if speech else '').strip()
    return content or DEFAULT_FRST_FIX_MESSAGE_TEMPLATE


def _free_speech_name(user):
    """The fix speech's name, suffixed if the user already has a speech by that name."""
    taken = set(Speech.objects.filter(owner=user).values_list('name', flat=True))
    name = FIX_MESSAGE_SPEECH_NAME
    counter = 2
    while name in taken:
        name = f'{FIX_MESSAGE_SPEECH_NAME} ({counter})'
        counter += 1
    return name


def ensure_fix_message_speech(user, content=None):
    """Return the user's fix speech, creating it with the default text if missing.

    With `content`, the speech's text is set to it; an empty value means the
    default, as an empty fix message always did.
    """
    text = (content or '').strip() if content is not None else None
    speech = fix_message_speech(user)
    if speech is None:
        speech = Speech.objects.create(
            owner=user,
            name=_free_speech_name(user),
            category=FIX_MESSAGE_SPEECH_CATEGORY,
            content=text or DEFAULT_FRST_FIX_MESSAGE_TEMPLATE,
            is_fix_message=True,
        )
        speech.analyzer_users.add(user)
        return speech
    if text is not None:
        speech.content = text or DEFAULT_FRST_FIX_MESSAGE_TEMPLATE
        speech.save(update_fields=['content', 'updated_at'])
    return speech
