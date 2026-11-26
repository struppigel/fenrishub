"""Rule set scoping helpers.

A "rule set key" identifies which subset of `ClassificationRule` rows applies to
an analysis. Two keys exist today; more may follow.

  - 'shared'          : the global rule set = rules from users in shared mode
                        (plus users that have no UserProfile row at all).
  - 'private:<uid>'   : only rules owned by user <uid>.

Resolution rules:
  - For a viewer/owner: their `UserProfile.rule_set_mode` decides.
  - For an upload: the recipient_user's mode decides; unassigned uploads are
    'shared'.
"""

SHARED_RULE_SET_KEY = 'shared'
PRIVATE_PREFIX = 'private:'


def resolve_user_rule_set_key(user) -> str:
    """Return the rule set key applicable to `user` as a viewer/owner."""
    if user is None or not getattr(user, 'is_authenticated', False):
        return SHARED_RULE_SET_KEY
    profile = getattr(user, 'fenris_profile', None)
    mode = getattr(profile, 'rule_set_mode', SHARED_RULE_SET_KEY) or SHARED_RULE_SET_KEY
    if mode == 'private':
        return f'{PRIVATE_PREFIX}{user.id}'
    return SHARED_RULE_SET_KEY


def resolve_effective_rule_set_key(uploaded_log) -> str:
    """Return the rule set key applied to analyses of `uploaded_log` for display."""
    return resolve_user_rule_set_key(uploaded_log.recipient_user)


def rule_set_label(key: str) -> str:
    """'shared' or 'private': how a rule set key is named to users and API clients."""
    return 'shared' if key == SHARED_RULE_SET_KEY else 'private'


def parse_rule_set_key(key: str):
    """Parse a key string into (scope, user_id). Unknown shapes fall back to shared."""
    if not key or key == SHARED_RULE_SET_KEY:
        return (SHARED_RULE_SET_KEY, None)
    if key.startswith(PRIVATE_PREFIX):
        try:
            return ('private', int(key[len(PRIVATE_PREFIX):]))
        except ValueError:
            return (SHARED_RULE_SET_KEY, None)
    return (SHARED_RULE_SET_KEY, None)


def keys_affected_by_owner(owner) -> list:
    """Rule set keys whose buckets depend on `owner`'s rules."""
    keys = [f'{PRIVATE_PREFIX}{owner.id}']
    profile = getattr(owner, 'fenris_profile', None)
    if profile is None or profile.rule_set_mode == SHARED_RULE_SET_KEY:
        keys.append(SHARED_RULE_SET_KEY)
    return keys


def invalidate_for_rule_owner(owner) -> None:
    """Invalidate in-memory buckets for `owner`'s keys.

    Persistent `UploadedLogAnalysis` rows are intentionally left in place.
    They will look briefly stale until the analyzer re-runs (which it does
    on every view), but the analyzer page renders them instantly while the
    fresh analysis runs in the background — much better UX than blanking
    every cached log every time any rule is edited.
    """
    from .analyzer import invalidate_rule_buckets_cache
    keys = keys_affected_by_owner(owner)
    for k in keys:
        invalidate_rule_buckets_cache(k)


def is_rule_restricted(user) -> bool:
    """True for a helper a superuser forced into their private rule set
    (training): they see no other owner's rules, nor verdicts of another
    rule set. Superusers and guests are never restricted."""
    if user is None or not getattr(user, 'is_authenticated', False) or user.is_superuser:
        return False
    try:
        profile = user.fenris_profile
    except Exception:  # RelatedObjectDoesNotExist: no profile row
        return False
    return bool(profile.force_private_rule_set)


def counts_visible_to(uploaded_log, user) -> bool:
    """Whether `user` may see `uploaded_log`'s count_* stats: they hold the
    recipient's verdicts, so a restricted helper sees them only on their own
    assigned logs (counted with their own rules)."""
    return not is_rule_restricted(user) or uploaded_log.recipient_user_id == user.id


def is_restricted_key(key: str) -> bool:
    """True when `key` is the private rule set of a restricted helper."""
    scope, user_id = parse_rule_set_key(key)
    if scope != 'private':
        return False
    from .models import UserProfile
    return UserProfile.objects.filter(
        user_id=user_id, force_private_rule_set=True, user__is_superuser=False,
    ).exists()


def set_forced_private(profile, forced: bool) -> None:
    """Force (or release) `profile`'s helper into their private rule set.

    Forcing makes the mode private and recomputes the stat counts of the
    helper's assigned logs off the request thread, so their chips show their
    own verdicts. Releasing leaves the mode private; the helper can switch it
    back on their profile page. Other unsaved changes to `profile` (an admin
    form's) are saved along with it."""
    stored = type(profile).objects.filter(pk=profile.pk).values('rule_set_mode', 'force_private_rule_set').first()
    old_mode = stored['rule_set_mode'] if stored else SHARED_RULE_SET_KEY
    was_forced = bool(stored and stored['force_private_rule_set'])
    profile.force_private_rule_set = forced
    profile.save()
    if old_mode != profile.rule_set_mode:
        on_user_rule_set_mode_changed(profile.user, old_mode, profile.rule_set_mode)
    if forced and not was_forced:
        from django.conf import settings
        from . import background
        if getattr(settings, 'TESTING', False):
            _recalculate_assigned_logs(profile.user_id)
            return
        background.start(_recalculate_assigned_logs, profile.user_id, name=f'forced-private-stats-{profile.user_id}')


def _recalculate_assigned_logs(user_id) -> None:
    from .models import UploadedLog
    for uploaded_log in UploadedLog.objects.filter(recipient_user_id=user_id).iterator():
        uploaded_log.recalculate_analysis_stats()


def on_user_rule_set_mode_changed(user, old_mode: str, new_mode: str) -> None:
    """Handle a profile rule_set_mode toggle by flushing in-memory buckets.

    See `invalidate_for_rule_owner` for why persistent cache rows are left
    in place rather than deleted.
    """
    from .analyzer import invalidate_rule_buckets_cache
    keys = [SHARED_RULE_SET_KEY, f'{PRIVATE_PREFIX}{user.id}']
    for k in keys:
        invalidate_rule_buckets_cache(k)
