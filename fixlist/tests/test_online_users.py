from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..models import UserProfile
from .factories import make_user


class OnlineUsersMiddlewareTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.login(username="alice", password="password123")

    def test_sets_last_seen_for_authenticated_user(self):
        before = timezone.now()
        self.client.get(reverse("rules"))
        profile = UserProfile.objects.get(user=self.user)
        self.assertIsNotNone(profile.last_seen)
        self.assertGreaterEqual(profile.last_seen, before)

    def test_skips_anonymous_requests(self):
        self.client.logout()
        UserProfile.objects.filter(user=self.user).delete()
        self.client.get(reverse("login"))
        self.assertFalse(UserProfile.objects.filter(user=self.user).exists())

    def test_throttles_updates_within_window(self):
        recent = timezone.now() - timedelta(seconds=5)
        UserProfile.objects.update_or_create(user=self.user, defaults={"last_seen": recent})
        self.client.get(reverse("rules"))
        profile = UserProfile.objects.get(user=self.user)
        self.assertEqual(profile.last_seen, recent)

    def test_updates_after_throttle_window(self):
        stale = timezone.now() - timedelta(seconds=60)
        UserProfile.objects.update_or_create(user=self.user, defaults={"last_seen": stale})
        self.client.get(reverse("rules"))
        profile = UserProfile.objects.get(user=self.user)
        self.assertGreater(profile.last_seen, stale)

    def test_updates_when_last_seen_is_null(self):
        UserProfile.objects.update_or_create(user=self.user, defaults={"last_seen": None})
        self.client.get(reverse("rules"))
        profile = UserProfile.objects.get(user=self.user)
        self.assertIsNotNone(profile.last_seen)

    def test_creates_profile_when_missing(self):
        UserProfile.objects.filter(user=self.user).delete()
        self.client.get(reverse("rules"))
        profile = UserProfile.objects.get(user=self.user)
        self.assertIsNotNone(profile.last_seen)


class OnlineUsersContextProcessorTests(TestCase):
    def setUp(self):
        self.alice = make_user(username="alice")
        self.bob = make_user(username="bob")
        self.charlie = make_user(username="charlie")
        self.client.login(username="alice", password="password123")

    def _set_last_seen(self, user, delta):
        UserProfile.objects.update_or_create(
            user=user, defaults={"last_seen": timezone.now() - delta}
        )

    def test_count_and_names_exclude_self_and_stale(self):
        self._set_last_seen(self.alice, timedelta(seconds=10))
        self._set_last_seen(self.bob, timedelta(minutes=2))
        self._set_last_seen(self.charlie, timedelta(minutes=30))
        response = self.client.get(reverse("rules"))
        online = response.context["online_users"]
        self.assertEqual(online["count"], 1)
        self.assertEqual(online["names"], ["bob"])

    def test_anonymous_request_sees_zero(self):
        self.client.logout()
        self._set_last_seen(self.alice, timedelta(seconds=10))
        response = self.client.get(reverse("login"))
        online = response.context["online_users"]
        self.assertEqual(online["count"], 0)
        self.assertEqual(online["names"], [])


class OnlineUsersTemplateTests(TestCase):
    def setUp(self):
        self.alice = make_user(username="alice")
        self.bob = make_user(username="bob")
        UserProfile.objects.update_or_create(
            user=self.alice, defaults={"last_seen": timezone.now()}
        )
        UserProfile.objects.update_or_create(
            user=self.bob, defaults={"last_seen": timezone.now()}
        )
        self.client.login(username="alice", password="password123")

    def test_base_template_renders_online_count_and_title(self):
        response = self.client.get(reverse("rules"))
        self.assertContains(response, "1 online")
        self.assertContains(response, 'title="bob"')
        self.assertNotContains(response, 'title="alice, bob"')
