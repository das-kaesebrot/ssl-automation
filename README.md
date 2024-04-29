# certbot-scripts

This folder contains scripts required for auto-renewal of Let's Encrypt issued certificates.

To use, either run `./renew-haproxy-cert.py` directly or install a cron job for `./renew-multiple-certs.sh` like so:

```cron
0 4 * * * root /path/to/script/renew-multiple-certs.sh mymail@example.com domain1.example.com domain2.example.com
```
