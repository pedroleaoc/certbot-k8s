# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest
from unittest import mock

from ops import model, testing

import charm


class TestCertbotK8sCharm(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(charm.CertbotK8sCharm)
        self.addCleanup(self.harness.cleanup)

    def _patch(self, obj, method, *args, **kwargs):
        """Patches the given method and returns its Mock."""
        patcher = mock.patch.object(obj, method, *args, **kwargs)
        mock_patched = patcher.start()
        self.addCleanup(patcher.stop)

        return mock_patched

    def test_certbot_nginx_pebble_ready(self):
        # Check the initial Pebble plan is empty.
        initial_plan = self.harness.get_container_pebble_plan("certbot-nginx")
        self.assertEqual(initial_plan.to_yaml(), "{}\n")

        # Set the configurations needed by the Charm.
        self.harness.begin_with_initial_hooks()
        self.harness.update_config({"email": "foo@li.sh", "agree-tos": True})

        # Get the nginx-certbot container from the model and emit PebbleEventReady.
        container = self.harness.model.unit.get_container("certbot-nginx")
        self.harness.charm.on.certbot_nginx_pebble_ready.emit(container)

        # Check we've got the plan we expected.
        updated_plan = self.harness.get_container_pebble_plan("certbot-nginx").to_dict()
        expected_plan = {
            "services": {
                "nginx": {
                    "override": "replace",
                    "summary": "nginx",
                    "command": "/docker-entrypoint.sh nginx -g 'daemon off;'",
                    "startup": "enabled",
                }
            },
        }
        self.assertEqual(expected_plan, updated_plan)

        # Check the service was started.
        service = self.harness.model.unit.get_container("certbot-nginx").get_service("nginx")
        self.assertTrue(service.is_running())

        # Ensure we set an ActiveStatus with no message.
        self.assertEqual(self.harness.model.unit.status, model.ActiveStatus())

    def test_config_changed(self):
        # Check that the Waiting Status is set if Pebble is not ready yet.
        container = self.harness.model.unit.get_container("certbot-nginx")
        mock_connect = self._patch(container, "can_connect", return_value=False)

        self.harness.begin_with_initial_hooks()
        self.assertIsInstance(self.harness.model.unit.status, model.WaitingStatus)

        # Pebble is not ready. There are no initial configurations, the Charm should be blocked.
        mock_connect.return_value = True
        self.harness.charm.on.certbot_nginx_pebble_ready.emit(container)
        expected_status = model.BlockedStatus("Please configure an email.")
        self.assertEqual(self.harness.model.unit.status, expected_status)

        # Configure the email. It should now expect the Terms of Service to be agreed upon.
        self.harness.update_config({"email": "foo@li.sh"})
        expected_status = model.BlockedStatus(
            "Let's Encrypt requires an agreement to their Terms of Service. "
            "Run juju config %s agree-tos=true" % self.harness.charm.app.name
        )
        self.assertEqual(self.harness.model.unit.status, expected_status)

        # Agree to the Terms of Service and expect the charm to be Active.
        self.harness.update_config({"agree-tos": True})
        self.assertEqual(self.harness.model.unit.status, model.ActiveStatus())
