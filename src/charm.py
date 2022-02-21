#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Module defining the Charmed operator for generating CA-signed Certificates."""

import base64
import logging
import os
import re

import kubernetes.client
from ops import charm, main, model

logger = logging.getLogger(__name__)

_SECRET_NAME_REGEX = re.compile("[^0-9a-zA-Z]")
_NGINX_WEBROOT = "/usr/share/nginx/html"
_LETS_ENCRYPT_BASE_DIR = "/etc/letsencrypt/live"


def _core_v1_api():
    """Use the V1 Kubernetes API."""
    return kubernetes.client.CoreV1Api()


class CertbotK8sCharm(charm.CharmBase):
    """A Juju Charm for generating CA-signed Certificates using certbot."""

    _authed = False

    def __init__(self, *args):
        super().__init__(*args)

        # General hooks:
        self.framework.observe(
            self.on.certbot_nginx_pebble_ready, self._on_certbot_nginx_pebble_ready
        )
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    def _on_certbot_nginx_pebble_ready(self, event):
        """Define and start the certbot-nginx Pebble Layer."""
        # Get a reference the container attribute on the PebbleReadyEvent
        container = event.workload

        # Define an initial Pebble layer configuration
        pebble_layer = {
            "summary": "certbot-nginx layer",
            "description": "Pebble config layer for certbox-nginx.",
            "services": {
                "nginx": {
                    "override": "replace",
                    "summary": "nginx",
                    "command": "/docker-entrypoint.sh nginx -g 'daemon off;'",
                    "startup": "enabled",
                }
            },
        }
        # Add initial Pebble config layer using the Pebble API
        container.add_layer("certbot-nginx", pebble_layer, combine=True)

        # Autostart any services that were defined with startup: enabled
        container.autostart()

        self._refresh_charm_status(container)

    def _on_config_changed(self, _):
        """Refreshes the service config."""
        is_active = self._refresh_charm_status()

        try:
            if is_active:
                self._ensure_certificate(self.model.config["service-hostname"])
        except kubernetes.client.exceptions.ApiException as ex:
            if ex.status == 403:
                logger.error(
                    "Insufficient permissions to list / create the Kubernetes Secrets, "
                    "will require 'juju trust` to be run"
                )
                self.unit.status = model.BlockedStatus(
                    "Insufficient permissions, try `juju trust %s --scope=cluster`" % self.app.name
                )
            else:
                raise

    def _refresh_charm_status(self, container=None):
        """Updates the Charm status.

        If the Pebble layer is not yet ready, the Charm status will be set to Waiting.
        If the Charm was not configured with an email to be used by certbot, the Charm status will
        be set to Blocked.
        If the user did not agree to the Terms of Service through Juju config, the Charm status
        will be set to Blocked.
        """
        # If not provided with a container, get one.
        container = container or self.unit.get_container("certbot-nginx")

        if not container.can_connect():
            self.unit.status = model.WaitingStatus("Waiting for Pebble to be ready.")
            return False

        if not self.model.config["email"]:
            self.unit.status = model.BlockedStatus("Please configure an email.")
            return False

        if not self.model.config["agree-tos"]:
            self.unit.status = model.BlockedStatus(
                "Let's Encrypt requires an agreement to their Terms of Service. "
                "Run juju config %s agree-tos=true" % self.app.name
            )
            return False

        self.unit.status = model.ActiveStatus()
        return True

    def _ensure_certificate(self, hostname):
        if not hostname:
            # Nothing to do.
            return

        # We're creating secrets based on the requested service-hostname. If it already exists,
        # we don't have to anything.
        secret_name = "%s-tls" % _SECRET_NAME_REGEX.sub("-", hostname)
        if self._secret_exists(secret_name):
            return

        cert, key = self._create_certificate(hostname)
        self._create_secret(secret_name, cert, key)

    def _create_certificate(self, hostname):
        """Creates the CA-verified certificate."""
        container = self.unit.get_container("certbot-nginx")
        command = [
            "certbot",
            "certonly",
            "--agree-tos",
            "-n",
            "-m",
            self.model.config["email"],
            "-d",
            hostname,
            "--webroot",
            "--webroot-path",
            _NGINX_WEBROOT,
        ]

        process = container.exec(command)
        process.wait_output()

        base_path = os.path.join(_LETS_ENCRYPT_BASE_DIR, hostname)
        cert_file = container.pull(os.path.join(base_path, "fullchain.pem"))
        key_file = container.pull(os.path.join(base_path, "privkey.pem"))

        return cert_file.read(), key_file.read()

    def _secret_exists(self, secret_name):
        """Checks whether the given secret exists in Kubernetes."""
        self.k8s_auth()
        api = _core_v1_api()

        secrets = api.list_namespaced_secret(namespace=self._namespace)
        return secret_name in [s.metadata.name for s in secrets.items]

    def _create_secret(self, secret_name, cert, key):
        """Creates the Kubernetes Secret in the Charm's namespace."""
        self.k8s_auth()
        api = _core_v1_api()

        encoded_cert = base64.b64encode(cert.encode("utf-8"))
        encoded_key = base64.b64encode(key.encode("utf-8"))
        body = kubernetes.client.V1Secret(
            api_version="v1",
            kind="Secret",
            type="kubernetes.io/tls",
            metadata=kubernetes.client.V1ObjectMeta(
                name=secret_name,
            ),
            data={
                "tls.crt": encoded_cert.decode("utf-8"),
                "tls.key": encoded_key.decode("utf-8"),
            },
        )

        api.create_namespaced_secret(
            namespace=self._namespace,
            body=body,
        )
        logger.info("Created secret '%s' in namespace %s", secret_name, self._namespace)

    @property
    def _namespace(self):
        """Return the namespace the Charm operates in."""
        return self.model.name

    def k8s_auth(self):
        """Authenticate to Kubernetes."""
        if self._authed:
            return

        kubernetes.config.load_incluster_config()
        self._authed = True


if __name__ == "__main__":
    main.main(CertbotK8sCharm)
