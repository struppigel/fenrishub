"""The trash of the soft-deletable models (uploads, fixlists, cases, case notes).

An object is "in the trash" while its `deleted_at` is set; querysets select
live or trashed rows with `SoftDeleteQuerySet.live()` / `.trashed()` and move
many rows at once with `.move_to_trash()`. Deletion-protected rows
(`is_protected`) are never deleted or trashed by a bulk action.
"""
from django.contrib import messages
from django.utils import timezone


def soft_delete(obj, *extra_update_fields) -> None:
    """Move one object to the trash."""
    obj.deleted_at = timezone.now()
    obj.save(update_fields=['deleted_at', *extra_update_fields])


def restore(obj, *extra_update_fields) -> None:
    """Bring one object back from the trash."""
    obj.deleted_at = None
    obj.save(update_fields=['deleted_at', *extra_update_fields])


def protected_names_error(request, names, *, verb) -> bool:
    """Flash why a bulk action stops when any of `names` is deletion-protected.

    Returns True when it did (the caller then redirects without acting).
    """
    names = sorted(names)
    if not names:
        return False
    messages.error(
        request,
        f'Deletion-protected, cannot {verb}: {", ".join(names)}. Remove protection first.',
    )
    return True


def empty_trash(trashed_items) -> tuple[int, int]:
    """Permanently delete the trashed items that are not deletion-protected.

    Emptying the trash sweeps everything at once, so protected items are kept
    back instead of aborting the whole action. Returns ``(deleted, kept)``.
    """
    items = list(trashed_items)
    deletable = [item for item in items if not item.is_protected]
    for item in deletable:
        item.delete()
    return len(deletable), len(items) - len(deletable)
