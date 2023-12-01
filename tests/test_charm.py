# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import base64
import os
import socket
import unittest
from unittest import mock

import kubernetes.client
from ops import model, testing

import charm


class TestCertbotK8sCharm(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(charm.CertbotK8sCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(True)
        self.harness.begin_with_initial_hooks()
        self.harness.charm._authed = True

    def _patch(self, obj, method, *args, **kwargs):
        """Patches the given method and returns its Mock."""
        patcher = mock.patch.object(obj, method, *args, **kwargs)
        mock_patched = patcher.start()
        self.addCleanup(patcher.stop)

        return mock_patched

    def _add_relation(self, relation_name, relator_name, relation_data):
        """Adds a relation to the charm."""
        relation_id = self.harness.add_relation(relation_name, relator_name)
        self.harness.add_relation_unit(relation_id, "%s/0" % relator_name)

        self.harness.update_relation_data(relation_id, relator_name, relation_data)
        return relation_id

    def test_certbot_nginx_pebble_ready(self):
        # Set the configurations and relations needed by the Charm.
        self.harness.update_config({"email": "foo@li.sh", "agree-tos": True})
        self._add_relation("ingress", "nginx-ingress-integrator", {})

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

    @mock.patch.object(charm.CertbotK8sCharm, "_ensure_certificate")
    @mock.patch.object(charm.CertbotK8sCharm, "_setup_ingress_route")
    def test_config_changed(self, mock_setup_route, mock_ensure_certificate):
        # Check that the Waiting Status is set if Pebble is not ready yet.
        container = self.harness.model.unit.get_container("certbot-nginx")
        mock_connect = self._patch(container, "can_connect", return_value=False)

        # Pebble is now ready, but there is no Ingress relation.
        mock_connect.return_value = True
        self.harness.charm.on.certbot_nginx_pebble_ready.emit(container)
        expected_status = model.BlockedStatus("Needs an ingress relation.")
        self.assertEqual(self.harness.model.unit.status, expected_status)

        # Add too many Ingress relations. It should be in Blocked State because of this.
        self._add_relation("ingress", "nginx-ingress-integrator", {})
        rel_id2 = self._add_relation("ingress", "nginx-ingress-integrator", {})
        expected_status = model.BlockedStatus("Too many ingress relations.")
        self.assertEqual(self.harness.model.unit.status, expected_status)

        # Leave only one Ingress relation. There are no initial configurations, the Charm should be
        # blocked.
        self.harness.remove_relation(rel_id2)
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

        # Agree to the Terms of Service.
        # On the first run, the charm should set up the ingress route. The event has to be defered
        # in order for the ingress relation data to get updated.
        mock_setup_route.return_value = True
        self.harness.update_config({"agree-tos": True})
        mock_ensure_certificate.assert_not_called()

        # The Charm encounters a 403 error because it's not trusted. The Charm should be blocked.
        mock_setup_route.return_value = False
        mock_ensure_certificate.side_effect = kubernetes.client.exceptions.ApiException(status=403)
        self.harness.charm.on.config_changed.emit()

        expected_status = model.BlockedStatus(
            "Insufficient permissions, try `juju trust %s --scope=cluster`"
            % self.harness.charm.app.name
        )
        self.assertEqual(self.harness.model.unit.status, expected_status)

        # If the Charm is trusted, it should now be Active.
        mock_ensure_certificate.side_effect = None
        self.harness.charm.on.config_changed.emit()
        self.assertEqual(self.harness.model.unit.status, model.ActiveStatus())

    @mock.patch("requests.get")
    @mock.patch("charm._core_v1_api")
    @mock.patch("socket.gethostbyname")
    def test_create_certificate(self, mock_gethost, mock_api, mock_get):
        # Initialize the Charm and add the necessary configuration and relation for it to
        # become Active.
        self._add_relation("ingress", "nginx-ingress-integrator", {})
        self.harness.update_config({"email": "foo@li.sh", "agree-tos": True})

        # We did not configure the service-hostname yet, so it shouldn't have checked if the
        # secret already exists.
        mock_api.assert_not_called()

        # Configure the service-hostname, but the secret already exists. It should not create a
        # certificate afterwards.
        mock_secret = mock.Mock()
        mock_secret.metadata.name = "foo-li-sh-tls"
        mock_list_secrets = mock_api.return_value.list_namespaced_secret
        mock_list_secrets.return_value.items = [mock_secret]
        container = self.harness.model.unit.get_container("certbot-nginx")
        mock_exec = self._patch(container, "exec")
        mock_pull = self._patch(container, "pull")
        mock_push = self._patch(container, "push")

        # On the first run, it's going to only set the service-hostname into the relation data
        # and then the event is deferred.
        self.harness.update_config({"service-hostname": "foo.li.sh"})

        msg = "Setting up an Ingress Route for foo.li.sh's HTTP Challenge."
        self.assertEqual(self.harness.model.unit.status, model.WaitingStatus(msg))
        expected_path = os.path.join("/usr/share/nginx/html/.well-known/acme-challenge/foo.test")
        mock_push.assert_called_once_with(
            path=expected_path, source="ignore me", encoding="utf-8", make_dirs=True
        )
        mock_exec.assert_not_called()

        # The secret already exists, the charm should become Active.
        self.harness.charm.on.config_changed.emit()

        self.assertEqual(self.harness.model.unit.status, model.ActiveStatus())
        mock_list_secrets.assert_called_once_with(namespace=self.harness.charm._namespace)
        mock_exec.assert_not_called()

        # Test the hostname not resolvable scenario. The Charm should end up in a Blocked Status.
        mock_list_secrets.return_value.items = []
        mock_gethost.side_effect = socket.error

        self.harness.charm.on.config_changed.emit()
        msg = "Cannot resolve hostname: 'foo.li.sh'"
        self.assertEqual(self.harness.model.unit.status, model.BlockedStatus(msg))

        # Reemit the config update event, it should check that the test file is reachable.
        mock_gethost.side_effect = None
        mock_response = mock_get.return_value
        mock_response.status_code = 404
        self.harness.charm.on.config_changed.emit()

        msg = "Cannot reach test file using Ingress Route. Retrying."
        self.assertEqual(self.harness.model.unit.status, model.WaitingStatus(msg))
        mock_get.assert_called_once_with(
            "http://foo.li.sh%s/foo.test" % charm._ACME_CHALLENGE_ROUTE
        )
        mock_exec.assert_not_called()

        # Reemit the config update event, it should now create the certificate.
        mock_pull.return_value.read.side_effect = ["some_cert", "some_key"]
        mock_response.status_code = 200
        self.harness.charm.on.config_changed.emit()

        self.assertEqual(self.harness.model.unit.status, model.ActiveStatus())
        command = [
            "certbot",
            "certonly",
            "--agree-tos",
            "-n",
            "-m",
            self.harness.model.config["email"],
            "-d",
            "foo.li.sh",
            "--webroot",
            "--webroot-path",
            charm._NGINX_WEBROOT,
        ]
        mock_exec.assert_called_once_with(command)

        base_path = os.path.join(charm._LETS_ENCRYPT_BASE_DIR, "foo.li.sh")
        mock_pull.assert_has_calls(
            [
                mock.call(os.path.join(base_path, "fullchain.pem")),
                mock.call(os.path.join(base_path, "privkey.pem")),
            ],
        )

        expected_body = kubernetes.client.V1Secret(
            api_version="v1",
            kind="Secret",
            type="kubernetes.io/tls",
            metadata=kubernetes.client.V1ObjectMeta(
                name="foo-li-sh-tls",
            ),
            data={
                "tls.crt": base64.b64encode("some_cert".encode("utf-8")).decode("utf-8"),
                "tls.key": base64.b64encode("some_key".encode("utf-8")).decode("utf-8"),
            },
        )
        mock_api.return_value.create_namespaced_secret.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=expected_body,
        )

        # The service-hostname in the relation data should NOT have been reset.
        relation = self.harness.model.get_relation("ingress")
        svc_hostname = relation.data[self.harness.charm.app]["service-hostname"]
        self.assertEqual("foo.li.sh", svc_hostname)

    @mock.patch.object(charm.CertbotK8sCharm, "_generate_certificate_and_secret")
    @mock.patch.object(charm.CertbotK8sCharm, "_check_ingress_route")
    @mock.patch.object(charm.CertbotK8sCharm, "_setup_ingress_route")
    @mock.patch.object(charm.CertbotK8sCharm, "_resolve_hostname")
    @mock.patch("charm._core_v1_api")
    def test_renew_certificate(
        self,
        mock_api,
        mock_resolve_host,
        mock_setup_ingress,
        mock_check_ingress,
        mock_generate_cert,
    ):
        # Initialize the Charm and add the necessary configuration and relation for it to
        # become Active.
        self._add_relation("ingress", "nginx-ingress-integrator", {})
        self.harness.update_config({"email": "foo@li.sh", "agree-tos": True})

        # Resetting after update_config, where these may have been called.
        mock_resolve_host.reset_mock()
        mock_setup_ingress.reset_mock()
        mock_check_ingress.reset_mock()

        mock_event = mock.Mock()

        with self.assertRaises(charm.CertbotK8sError) as cm:
            self.harness.charm._on_renew_certificate_action(mock_event)

        self.assertEqual("service-hostname is not set.", str(cm.exception))

        self.harness.update_config({"service-hostname": "service.com"})

        # The hostname is not resolvable.
        mock_resolve_host.return_value = False

        with self.assertRaises(charm.CertbotK8sError) as cm:
            self.harness.charm._on_renew_certificate_action(mock_event)

        self.assertEqual("Cannot resolve hostname: 'service.com'", str(cm.exception))

        # The hostname is now resolvable.
        mock_resolve_host.return_value = True

        # configure the secrets
        mock_secret = mock.Mock()
        mock_secret.metadata.name = "foo-lish-tls"
        mock_list_secrets = mock_api.return_value.list_namespaced_secret
        mock_list_secrets.return_value.items = [mock_secret]

        # Configure trying to setup ingress route, but it fails.
        mock_setup_ingress.return_value = True
        mock_check_ingress.return_value = False

        with self.assertRaises(charm.CertbotK8sError) as cm:
            self.harness.charm._on_renew_certificate_action(mock_event)

        mock_resolve_host.assert_called_with("service.com")
        mock_setup_ingress.assert_called_with("service.com")
        mock_check_ingress.assert_called_with("service.com")

        # the route check should fail after 60 times
        self.assertEqual("Cannot reach test file using Ingress Route.", str(cm.exception))

        # Configure trying to setup ingress route, but it succeeds.
        mock_check_ingress.return_value = True
        self.harness.charm._on_renew_certificate_action(mock_event)

        mock_generate_cert.assert_called_once_with("service.com", "service-com-tls")

        mock_event.set_results.assert_called_once_with(
            {"result": "Certificate renewed for service.com"}
        )

        # If the certificate generation fails, the action should fail with the same error.
        mock_generate_cert.side_effect = kubernetes.client.exceptions.ApiException(status=403)

        self.assertRaises(
            kubernetes.client.exceptions.ApiException,
            self.harness.charm._on_renew_certificate_action,
            mock_event,
        )

    @mock.patch("charm._core_v1_api")
    @mock.patch.object(charm.CertbotK8sCharm, "_create_certificate")
    def test_generate_certificate_and_secret(self, mock_create_cert, mock_api):
        self._add_relation("ingress", "nginx-ingress-integrator", {})
        self.harness.update_config({"email": "foo@li.sh", "agree-tos": True})

        mock_create_cert.return_value = ("some_cert", "some_key")

        secret_name = "service-com-tls"

        # The secret should be created, since we don't have one.
        mock_api.return_value.list_namespaced_secret.return_value.items = []
        self.harness.charm._generate_certificate_and_secret("service.com", secret_name)
        mock_api.return_value.create_namespaced_secret.assert_called_once()

        # The secret should be replaced, since we have one.
        mock_secret = mock.Mock()
        mock_secret.metadata.name = secret_name
        mock_api.return_value.list_namespaced_secret.return_value.items = [mock_secret]
        self.harness.charm._generate_certificate_and_secret("service.com", secret_name)
        mock_api.return_value.replace_namespaced_secret.assert_called_once_with(
            name=secret_name, namespace=self.harness.model.name, body=mock.ANY
        )

    @mock.patch("charm._core_v1_api")
    def test_get_secret_name_action(self, mock_api):
        mock_event = mock.Mock()

        # The email, agree-tos, service-hostname config options are not set, which means that
        # there is no certificate to get.
        self.assertRaises(
            charm.CertbotK8sError, self.harness.charm._on_get_secret_name_action, mock_event
        )

        self.harness.update_config({"email": "foo@lish"})
        self.assertRaises(
            charm.CertbotK8sError, self.harness.charm._on_get_secret_name_action, mock_event
        )

        self.harness.update_config({"agree-tos": True})
        self.assertRaises(
            charm.CertbotK8sError, self.harness.charm._on_get_secret_name_action, mock_event
        )

        # Setting the service-hostname config option. Test the case in which the secret does
        # not exist, in which case an Exception should be raised.
        mock_list_secrets = mock_api.return_value.list_namespaced_secret
        mock_list_secrets.return_value.items = []
        self.harness.update_config({"service-hostname": "foo.lish"})

        self.assertRaises(
            charm.CertbotK8sError, self.harness.charm._on_get_secret_name_action, mock_event
        )
        mock_list_secrets.assert_called_once_with(namespace=self.harness.model.name)

        # The secret now exists. The action should now succeed.
        mock_secret = mock.Mock()
        fake_secret_name = "foo-lish-tls"
        mock_secret.metadata.name = fake_secret_name
        mock_list_secrets.return_value.items = [mock_secret]

        self.harness.charm._on_get_secret_name_action(mock_event)

        mock_event.set_results.assert_called_once_with({"result": fake_secret_name})
