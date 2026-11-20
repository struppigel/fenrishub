"""Folders too broad to speak for the files inside them (a drive root,
Windows, Program Files, a user profile, ...) or whose files say nothing about
each other (Temp, browser caches, System32)."""

import re


# Folders too broad to speak for the files inside them: a drive root, Windows,
# Program Files (and its Common Files / WindowsApps), ProgramData, a user
# profile and its AppData / Desktop / Downloads / Documents folders.
_BROAD_FOLDER_RE = re.compile(
    r'^[a-z]:(?:\\(?:windows|programdata'
    r'|program files(?: \(x86\))?(?:\\(?:common files|windowsapps))?'
    r'|users(?:\\[^\\]+(?:\\(?:desktop|downloads|documents'
    r'|appdata(?:\\(?:local|roaming|locallow)(?:\\programs)?)?))?)?))?$'
)


def is_broad_folder(key):
    """True for a folder key too broad to speak for the files inside it."""
    return bool(_BROAD_FOLDER_RE.match((key or '').rstrip('\\')))


# Folders whose files have nothing to do with each other besides the broad
# ones: Temp, the browser caches, Windows' own system folders.
_BROAD_PARENT_RE = re.compile(
    r'^[a-z]:\\(?:windows(?:\\temp|\\system32(?:\\drivers|\\tasks)?|\\syswow64)'
    r'|users\\[^\\]+\\appdata\\local(?:\\temp|\\microsoft\\windows\\(?:inetcache|webcache)))$'
)


def is_broad_parent(key):
    """True for a folder whose files say nothing about each other (siblings,
    a folder line's contents): the broad folders, Temp, the browser caches,
    System32."""
    key = (key or '').rstrip('\\')
    return is_broad_folder(key) or bool(_BROAD_PARENT_RE.match(key))
