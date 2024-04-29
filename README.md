# certbot-scripts

This folder contains scripts required for auto-renewal of Let's Encrypt issued certificates.

To use, either run `./renew_cert.py` directly or install a cron job for `./renew-multiple-certs.py` like so:

```cron
0 4 * * * root /path/to/script/renew-multiple-certs.py -s -m mymail@example.com -D domain1.example.com domain2.example.com
```

To see script usage, run the following commands:

```bash
./renew_cert.py -h
```
```bash
./renew-multiple-certs.py -h
```

## HAProxy config

To allow redirection of Let's Encrypt renewal requests to certbot, add the following config settings to HAProxy.

```haproxy
frontend http_in
	# bind IPv4 and IPv6
	bind *:80
	bind :::80

	# your regular config goes here

	# Test URI to see if its a letsencrypt request
	# Required for automatic renewals
	# has to be redirected in the HTTP section, not HTTPS
	acl letsencrypt-acl path_beg /.well-known/acme-challenge/
	use_backend letsencrypt_backend if letsencrypt-acl

# LE Backend
backend letsencrypt_backend
	server letsencrypt 127.0.0.1:8888

```