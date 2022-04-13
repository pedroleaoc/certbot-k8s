# Certbot Kubernetes Charm

## Description

In order to access your applications securely through HTTPS, you are going to need a TLS certificate. You could generate your own self-signed certificate. However, using such a certificate will cause your browser to issue a warning when accessing your applications because the certificate is not verified by a trusted Certificate Authority (CA).

This Charm provides a way to easily obtain a CA-verified certificate, which can then be used by your services.

## Usage

This Charm requires you to have a publicly available DNS hostname, which is meant to be used by your applications. Without it, the CA will not be able to verify your ownership of the hostname you're generating the certificate for, and the verification process will fail.

To deploy this charm, simply run:

```bash
juju deploy --trust cerbot-k8s --channel=edge
```

Next, this charm will require a relation with an ``nginx-ingress-integrator`` charm, which will be used to automatically set up the Ingress Route required in order to solve the CA's ACME HTTP Challenge, which is required in proving the ownership of the hostname you're generating the certificate for.

To deploy the ``nginx-ingress-integrator`` charm and relate it to the ``certbot-k8s`` charm, run:

```bash
juju deploy --trust nginx-ingress-integrator
juju relate cerbot-k8s nginx-ingress-integrator
```

Next, you need to configure the email and agree with the [Terms of Service](https://letsencrypt.org/repository/) needed to use the Let's Encrypt CA:

```bash
juju config certbot-k8s email=your@email agree-tos=true
```

To generate a certificate for your hostname, simply run:

```bash
juju config certbot-k8s service-hostname=your-hostname
```

After a few moments, and if there were no issues encountered, a Kubernetes Secret containing your TLS certificate will have been generated. To get the secret name, run:

```bash
juju run-action certbot-k8s/0 get-secret-name --wait
```

If the Kubernetes Secret has been generated, the above command will return the Secret name. If it was not, it will result in an error, in which case you should check the ``juju debug-log``.

The Kubernetes Secret Name mentioned above can then be used by the ``nginx-ingress-integrator`` charms as well:

```bash
juju config another-nginx-ingress-integrator tls-secret-name=$SECRET_NAME
```

The command above will configure Ingress-level TLS termination.


## Relations

This charm requires an ``ingress`` relation, typically provided by the ``nginx-ingress-integrator`` charm.

## OCI Images

The image used by this charm is uploaded as a charm resource into charmhub and deployed automatically with the charm. The image is based on the ``nginx`` Docker image, and has ``certbot`` installed. Details on how to build your image can be found [here](docker/README.md).

## Charm releases

This repository is configured to automatically build and publish a new Charm revision after a Pull Request merges. For more information, see [here](docs/CharmPublishing.md).

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and `CONTRIBUTING.md` for developer guidance.
