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
    """Invalidate in-memory buckets and stale cached analyses for `owner`'s keys."""
    from .analyzer import invalidate_rule_buckets_cache
    from .models import UploadedLogAnalysis
    keys = keys_affected_by_owner(owner)
    for k in keys:
        invalidate_rule_buckets_cache(k)
    UploadedLogAnalysis.objects.filter(rule_set_key__in=keys).delete()


def on_user_rule_set_mode_changed(user, old_mode: str, new_mode: str) -> None:
    """Handle a profile rule_set_mode toggle by flushing affected caches."""
    from .analyzer import invalidate_rule_buckets_cache
    from .models import UploadedLogAnalysis
    keys = [SHARED_RULE_SET_KEY, f'{PRIVATE_PREFIX}{user.id}']
    for k in keys:
        invalidate_rule_buckets_cache(k)
    UploadedLogAnalysis.objects.filter(rule_set_key__in=keys).delete()
