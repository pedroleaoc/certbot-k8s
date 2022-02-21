## certbot-nginx image

The image is based on the nginx Docker image, and has certbot installed. It is meant
to be used to resolve HTTP challenges from CAs in order to prove ownership of hostnames.

### How to build

```bash
docker build -t yourregistry/certbot-nginx:0.1.0 --build-arg VERSION=0.1.0 .
docker push yourregistry/certbot-nginx:0.1.0
```
