#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Module defining the Charmed operator for generating CA-signed Certificates."""

import logging

from ops import charm, main, model

logger = logging.getLogger(__name__)


class CertbotK8sCharm(charm.CharmBase):
    """A Juju Charm for generating CA-signed Certificates using certbot."""

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
        self._refresh_charm_status()

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
            return

        if not self.model.config["email"]:
            self.unit.status = model.BlockedStatus("Please configure an email.")
            return

        if not self.model.config["agree-tos"]:
            self.unit.status = model.BlockedStatus(
                "Let's Encrypt requires an agreement to their Terms of Service. "
                "Run juju config %s agree-tos=true" % self.app.name
            )
            return

        self.unit.status = model.ActiveStatus()


if __name__ == "__main__":
    main.main(CertbotK8sCharm)
